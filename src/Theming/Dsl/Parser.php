<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
/**
 * Парсер logic-less Template DSL (ADR-0013) в AST из простых массивов.
 *
 * Синтаксис:
 *   {{ path }}               вывод с HTML-экранированием
 *   {{ path | filter }}      фильтр: attr, url или helper из whitelist
 *   {% if [not] path %} … {% else %} … {% endif %}
 *   {% each path as name %} … {% endeach %}
 *   {% include "name" %}
 *   {# комментарий #}
 *
 * path = ident(.ident)*. Нет выражений, вызовов, литералов (кроме имени include).
 * AST — только данные; он интерпретируется Renderer'ом и никогда не превращается в PHP.
 */
#[AbuserStory('template-code-exec')]
#[Mitigation(cwe: 'CWE-94', description: 'Logic-less grammar: no expressions or calls; AST is interpreted, never compiled to PHP')]
#[Mitigation(cwe: 'CWE-1336', description: 'Template names are TemplateName primitives; include depth bounded')]
#[AssetId('bastion-app')]
final class Parser
{
    private const IDENT = '[a-z_][a-z0-9_]*';
    private const PATH = self::IDENT . '(?:\.' . self::IDENT . ')*';
    public const BUILTIN_FILTERS = ['attr', 'url'];

    /** @var list<array{kind: string, body: string, line: int}> */
    private array $tokens = [];
    private int $pos = 0;
    private string $name = '';

    /** @param list<string> $helpers имена helper'ов, зарегистрированных расширениями с правом render */
    public function __construct(private readonly array $helpers = [])
    {
    }

    /** @return list<array<string, mixed>> */
    public function parse(string $source, TemplateName $name): array
    {
        $this->name = $name->toNative();
        if (!mb_check_encoding($source, 'UTF-8')) {
            throw TemplateSyntaxError::at($this->name, 1, 'Template must be valid UTF-8');
        }
        $this->tokens = $this->tokenize($source);
        $this->pos = 0;

        $nodes = $this->parseNodes([]);
        if ($this->pos < count($this->tokens)) {
            $t = $this->tokens[$this->pos];
            throw TemplateSyntaxError::at($this->name, $t['line'], "Unexpected {$t['body']}");
        }
        return $nodes;
    }

    /** @return list<array{kind: string, body: string, line: int}> */
    private function tokenize(string $source): array
    {
        $parts = preg_split('/(\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\})/s', $source, -1, PREG_SPLIT_DELIM_CAPTURE);
        $tokens = [];
        $line = 1;
        foreach ($parts === false ? [] : $parts as $i => $part) {
            if ($i % 2 === 0) {
                if (preg_match('/\{\{|\{%|\{#|\}\}|%\}|#\}/', $part)) {
                    throw TemplateSyntaxError::at($this->name, $line, 'Unbalanced tag delimiter');
                }
                if ($part !== '') {
                    $tokens[] = ['kind' => 'text', 'body' => $part, 'line' => $line];
                }
            } else {
                $kind = match (substr($part, 0, 2)) { '{{' => 'out', '{%' => 'tag', default => 'comment' };
                if ($kind !== 'comment') {
                    $tokens[] = ['kind' => $kind, 'body' => trim(substr($part, 2, -2)), 'line' => $line];
                }
            }
            $line += substr_count($part, "\n");
        }
        return $tokens;
    }

    /**
     * Разбирает узлы до одного из закрывающих тегов (не потребляя его).
     * @param list<string> $terminators
     * @return list<array<string, mixed>>
     */
    private function parseNodes(array $terminators): array
    {
        $nodes = [];
        while ($this->pos < count($this->tokens)) {
            $t = $this->tokens[$this->pos];
            if ($t['kind'] === 'tag' && in_array($t['body'], $terminators, true)) {
                return $nodes;
            }
            $this->pos++;
            $nodes[] = match ($t['kind']) {
                'text' => ['t' => 'text', 'v' => $t['body']],
                'out' => $this->parseOutput($t),
                default => $this->parseTag($t),
            };
        }
        if ($terminators !== []) {
            throw TemplateSyntaxError::at($this->name, $this->lastLine(), 'Unclosed block, expected ' . implode('/', $terminators));
        }
        return $nodes;
    }

    /** @param array{kind: string, body: string, line: int} $t */
    private function parseOutput(array $t): array
    {
        if (!preg_match('/^(' . self::PATH . ')(?:\s*\|\s*(' . self::IDENT . '))?$/', $t['body'], $m)) {
            throw TemplateSyntaxError::at($this->name, $t['line'], 'Invalid output expression');
        }
        $filter = $m[2] ?? '';
        if ($filter !== '' && !in_array($filter, self::BUILTIN_FILTERS, true) && !in_array($filter, $this->helpers, true)) {
            throw TemplateSyntaxError::at($this->name, $t['line'], "Unknown filter {$filter}");
        }
        return ['t' => 'out', 'path' => explode('.', $m[1]), 'f' => $filter];
    }

    /** @param array{kind: string, body: string, line: int} $t */
    private function parseTag(array $t): array
    {
        if (preg_match('/^if\s+(not\s+)?(' . self::PATH . ')$/', $t['body'], $m)) {
            $then = $this->parseNodes(['else', 'endif']);
            $else = [];
            if ($this->consume('else')) {
                $else = $this->parseNodes(['endif']);
            }
            $this->expect('endif', $t['line']);
            return ['t' => 'if', 'not' => $m[1] !== '', 'path' => explode('.', $m[2]), 'then' => $then, 'else' => $else];
        }
        if (preg_match('/^each\s+(' . self::PATH . ')\s+as\s+(' . self::IDENT . ')$/', $t['body'], $m)) {
            $body = $this->parseNodes(['endeach']);
            $this->expect('endeach', $t['line']);
            return ['t' => 'each', 'path' => explode('.', $m[1]), 'as' => $m[2], 'body' => $body];
        }
        if (preg_match('/^include\s+"([^"]*)"$/', $t['body'], $m)) {
            if (!TemplateName::tryParse($m[1])) {
                throw TemplateSyntaxError::at($this->name, $t['line'], 'Invalid include name');
            }
            return ['t' => 'include', 'name' => $m[1]];
        }
        throw TemplateSyntaxError::at($this->name, $t['line'], 'Unknown or misplaced tag');
    }

    private function consume(string $tag): bool
    {
        $t = $this->tokens[$this->pos] ?? null;
        if ($t !== null && $t['kind'] === 'tag' && $t['body'] === $tag) {
            $this->pos++;
            return true;
        }
        return false;
    }

    private function expect(string $tag, int $openedAt): void
    {
        if (!$this->consume($tag)) {
            throw TemplateSyntaxError::at($this->name, $openedAt, "Block not closed with {$tag}");
        }
    }

    private function lastLine(): int
    {
        return $this->tokens === [] ? 1 : $this->tokens[array_key_last($this->tokens)]['line'];
    }
}
