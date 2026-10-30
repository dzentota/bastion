<?php
declare(strict_types=1);

namespace Bastion\Theming\Dsl;

use Dzentota\TemplateVariable\TemplateVariable;
use dzentota\TypedValue\Typed;
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Интерпретатор AST Template DSL. Никогда не исполняет PHP из темы.
 * Весь вывод экранируется (dzentota/template-variable); неэкранированный вывод
 * возможен только для SafeHtml, которое создаёт ядро.
 */
#[AbuserStory('stored-xss-block')]
#[AbuserStory('comment-xss')]
#[Mitigation(cwe: 'CWE-79', description: 'Template output escaped by context; url filter allowlists schemes; raw output only for core-issued SafeHtml')]
#[AssetId('bastion-app')]
final class Renderer
{
    private const MAX_INCLUDE_DEPTH = 8;

    /** @var array<string, \Closure(string): string> */
    private array $helpers;
    private readonly Parser $parser;

    /** @param array<string, \Closure(string): string> $helpers результат helper'а будет экранирован */
    public function __construct(
        private readonly TemplateSource $source,
        private readonly ?SignedAstCache $cache = null,
        array $helpers = [],
    ) {
        foreach (array_keys($helpers) as $helper) {
            if (in_array($helper, Parser::BUILTIN_FILTERS, true) || !preg_match('/^[a-z_][a-z0-9_]*$/', $helper)) {
                throw new \InvalidArgumentException("Invalid helper name {$helper}");
            }
        }
        $this->helpers = $helpers;
        $this->parser = new Parser(array_keys($helpers));
    }

    /** @param array<string, mixed> $context */
    public function render(TemplateName $name, array $context): string
    {
        return $this->renderTemplate($name, $context, 0);
    }

    /** @param array<string, mixed> $context */
    private function renderTemplate(TemplateName $name, array $context, int $depth): string
    {
        if ($depth > self::MAX_INCLUDE_DEPTH) {
            throw new TemplateSyntaxError("Include depth exceeded at {$name->toNative()}");
        }
        return $this->renderNodes($this->ast($name), $context, $depth);
    }

    /** @return list<array<string, mixed>> */
    private function ast(TemplateName $name): array
    {
        $source = $this->source->load($name);
        $ast = $this->cache?->get($name, $source);
        if ($ast === null) {
            $ast = $this->parser->parse($source, $name);
            $this->cache?->put($name, $source, $ast);
        }
        return $ast;
    }

    /**
     * @param list<array<string, mixed>> $nodes
     * @param array<string, mixed> $ctx
     */
    private function renderNodes(array $nodes, array $ctx, int $depth): string
    {
        $out = '';
        foreach ($nodes as $node) {
            $out .= match ($node['t']) {
                'text' => $node['v'],
                'out' => $this->output($this->lookup($ctx, $node['path']), $node['f']),
                'if' => $this->truthy($this->lookup($ctx, $node['path'])) !== $node['not']
                    ? $this->renderNodes($node['then'], $ctx, $depth)
                    : $this->renderNodes($node['else'], $ctx, $depth),
                'each' => $this->each($node, $ctx, $depth),
                'include' => $this->renderTemplate(TemplateName::fromNative($node['name']), $ctx, $depth + 1),
                default => throw new \LogicException('Unknown AST node'),
            };
        }
        return $out;
    }

    /** @param array<string, mixed> $node @param array<string, mixed> $ctx */
    private function each(array $node, array $ctx, int $depth): string
    {
        $items = $this->lookup($ctx, $node['path']);
        if (!is_iterable($items)) {
            return '';
        }
        $out = '';
        foreach ($items as $item) {
            $out .= $this->renderNodes($node['body'], [$node['as'] => $item] + $ctx, $depth);
        }
        return $out;
    }

    /**
     * Доступ только к ключам массивов. Методы и свойства объектов недоступны.
     * @param array<string, mixed> $ctx
     * @param list<string> $path
     */
    private function lookup(array $ctx, array $path): mixed
    {
        $value = $ctx;
        foreach ($path as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return null;
            }
            $value = $value[$segment];
        }
        return $value;
    }

    private function truthy(mixed $value): bool
    {
        if ($value instanceof Typed) {
            $value = $value->toNative();
        }
        return !($value === null || $value === false || $value === '' || $value === [] || $value === 0);
    }

    private function output(mixed $value, string $filter): string
    {
        if ($value instanceof SafeHtml) {
            return $filter === '' ? $value->toString() : $this->escape($value->toString(), 'attr');
        }
        $string = $this->stringify($value);
        return match ($filter) {
            '' => $this->escape($string, 'html'),
            'attr' => $this->escape($string, 'attr'),
            // dzentota/template-variable: allowlist схем (http/https/mailto/относительные), иначе "#"
            'url' => $this->escape($string, 'url_attr'),
            default => $this->escape(($this->helpers[$filter])($string), 'html'),
        };
    }

    private function stringify(mixed $value): string
    {
        if ($value instanceof Typed) {
            $value = $value->toNative();
        }
        return match (true) {
            $value === null => '',
            is_bool($value) => $value ? '1' : '',
            is_scalar($value) => (string) $value,
            default => '', // массивы и объекты не печатаются
        };
    }

    private function escape(string $value, string $context): string
    {
        return TemplateVariable::create($value)($context);
    }
}
