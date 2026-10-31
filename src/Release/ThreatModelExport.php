<?php
declare(strict_types=1);

namespace Bastion\Release;

use HybridTM\Analysis\{AnalysisOptions, MitigationIndex, RuleEngine};
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Compiler\AstScanner;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\YamlKbLoader;

/**
 * Экспорт модели угроз для сайта документации (релиз 6, ADR-0023): модель hybridtm, покрытие
 * Abuser Stories, меры из атрибутов кода, связь историй с тестами атак и находки анализатора
 * вместе с решениями по ним. Только для сборки релиза — hybridtm в require-dev; веб-процесс
 * читает уже готовый JSON и PHP-модель не исполняет.
 * Формат стабилен и детерминирован: одинаковый вход → одинаковые байты.
 */
final class ThreatModelExport
{
    public const FORMAT = 'bastion-threat-model';
    public const VERSION = 1;

    /** @return array<string, mixed> */
    public static function build(string $root): array
    {
        $model = require $root . '/threat-model.php';
        if (!$model instanceof ThreatModel) {
            throw new \UnexpectedValueException('threat-model.php must return a ThreatModel');
        }
        $canonical = (new ModelJsonCodec())->encode($model);
        $ast = (new AstScanner())->scan($root . '/src');
        $kb = (new YamlKbLoader())->load([$root . '/vendor/hybridtm/hybridtm/apps/api/kb']);
        $result = (new RuleEngine())->analyze($model, $kb, new AnalysisOptions(
            includeSuppressed: true, collectTraces: false,
            mitigations: MitigationIndex::fromDiscoveries($ast->mitigations),
            abuserStoryRefs: $ast->abuserStoryRefs, checkStories: true,
        ));
        $backlog = require $root . '/threat-model/backlog.php';
        $rel = static fn (string $file): string => str_starts_with($file, $root . '/') ? substr($file, strlen($root) + 1) : basename($file);

        $boundaryOf = [];
        $boundaries = [];
        foreach (self::list($canonical['trustBoundaries'] ?? []) as $b) {
            $boundaries[] = ['id' => self::s($b, 'id'), 'name' => self::s($b, 'name'), 'type' => self::s($b, 'type')];
            foreach (self::strs(self::arr($b)['contains'] ?? []) as $member) {
                $boundaryOf[$member] = self::s($b, 'id');
            }
        }
        $components = [];
        foreach (self::list($canonical['components'] ?? []) as $c) {
            $o = self::arr(self::arr($c)['overrides'] ?? null);
            $components[] = [
                'id' => self::s($c, 'id'), 'name' => self::s($c, 'name'),
                'type' => self::s($o, 'type'), 'technology' => self::s($o, 'technology'),
                'internet' => ($o['internet'] ?? false) === true,
                'actor' => in_array('threat_actor', self::strs(self::arr($c)['traits'] ?? []), true),
                'boundary' => $boundaryOf[self::s($c, 'id')] ?? null,
            ];
        }
        $flows = [];
        foreach (self::list($canonical['dataFlows'] ?? []) as $f) {
            $flows[] = [
                'id' => self::s($f, 'id'), 'from' => self::s($f, 'sourceId'), 'to' => self::s($f, 'targetId'),
                'description' => self::s($f, 'description'), 'protocol' => self::s($f, 'protocol'),
                'authentication' => self::s($f, 'authentication'), 'authorization' => self::s($f, 'authorization'),
                'sent' => self::strs(self::arr($f)['dataSent'] ?? []), 'received' => self::strs(self::arr($f)['dataReceived'] ?? []),
            ];
        }
        $dataAssets = [];
        foreach (self::list($canonical['dataAssets'] ?? []) as $d) {
            $dataAssets[] = ['id' => self::s($d, 'id'), 'name' => self::s($d, 'name'), 'confidentiality' => self::s($d, 'confidentiality'), 'integrity' => self::s($d, 'integrity')];
        }

        $mitigationsByStory = [];
        foreach ($ast->mitigations as $m) {
            foreach ($m->abuserStoryIds as $story) {
                $loc = $m->location;
                $mitigationsByStory[$story][] = [
                    'cwe' => $m->cwe, 'description' => $m->description,
                    'file' => $loc !== null ? $rel($loc->file) : '', 'line' => $loc->line ?? 0,
                    'symbol' => $loc !== null ? trim(($loc->class ?? '') . ($loc->method !== null ? '::' . $loc->method : ''), ':') : '',
                ];
            }
        }
        $coverage = [];
        foreach ($result->storyCoverage as $c) {
            $coverage[$c->storyId] = $c;
        }
        $known = array_map(static fn (mixed $a) => self::s($a, 'title'), self::list($canonical['abuseCases'] ?? []));
        $tests = self::testsByStory($root, $known);
        $stories = [];
        foreach (self::list($canonical['abuseCases'] ?? []) as $a) {
            $id = self::s($a, 'title');
            $cov = $coverage[$id] ?? null;
            $status = in_array($id, is_array($backlog) ? $backlog : [], true) ? 'backlog' : ($cov?->status->value ?? 'uncovered');
            $ms = $mitigationsByStory[$id] ?? [];
            usort($ms, static fn (array $x, array $y) => [$x['cwe'], $x['file'], $x['line']] <=> [$y['cwe'], $y['file'], $y['line']]);
            $stories[] = [
                'id' => $id, 'title' => self::s($a, 'text'), 'asA' => self::s($a, 'asA'), 'iWant' => self::s($a, 'iWant'), 'soThat' => self::s($a, 'soThat'),
                'actor' => self::s($a, 'actorId'), 'assets' => self::strs(self::arr($a)['assetIds'] ?? []),
                'requiredCwes' => self::strs(self::arr($a)['requiredCwes'] ?? []),
                'missingCwes' => $cov !== null ? $cov->missingCwes : [], 'status' => $status,
                'mitigations' => $ms, 'tests' => $tests[$id] ?? [],
            ];
        }

        $decisions = [];
        foreach (self::list($canonical['riskTracking'] ?? []) as $r) {
            $decisions[self::s($r, 'findingStableId')] = ['status' => self::s($r, 'status'), 'justification' => self::s($r, 'justification')];
        }
        $findings = [];
        foreach ($result->findings as $f) {
            $j = $f->jsonSerialize();
            $findings[] = [
                'id' => $f->stableId, 'threat' => self::s($j, 'threatId'), 'title' => self::s($j, 'title'), 'description' => self::s($j, 'description'),
                'severity' => self::s($j, 'severity'), 'subject' => self::s($j, 'subject'),
                'stride' => self::strs($j['stride'] ?? []),
                'cwe' => array_map(static fn (mixed $c) => 'CWE-' . (is_scalar($c) ? (string) $c : ''), self::list(is_array($j['standards'] ?? null) ? ($j['standards']['cwe'] ?? []) : [])),
                'decision' => $decisions[$f->stableId] ?? null,
            ];
        }
        usort($findings, static fn (array $a, array $b) => [self::rank($b['severity']), $a['threat'], $a['subject']] <=> [self::rank($a['severity']), $b['threat'], $b['subject']]);

        return [
            'format' => self::FORMAT, 'version' => self::VERSION,
            'title' => self::s(is_array($canonical['model'] ?? null) ? $canonical['model'] : [], 'title'),
            'inputHash' => $result->inputHash,
            'boundaries' => $boundaries, 'components' => $components, 'flows' => $flows, 'dataAssets' => $dataAssets,
            'stories' => $stories, 'findings' => $findings,
        ];
    }

    /**
     * Abuser stories → тесты атак: известные модели id, названные в комментарии
     * «Abuser story: …» / «Abuser stories: …» (docblock класса или метода, в т.ч. многострочный).
     * @param list<string> $known
     * @return array<string, list<array{file: string, class: string}>>
     */
    private static function testsByStory(string $root, array $known): array
    {
        $out = [];
        $files = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/tests', \FilesystemIterator::SKIP_DOTS)) as $f) {
            if ($f instanceof \SplFileInfo && str_ends_with($f->getFilename(), 'Test.php')) {
                $files[] = $f->getPathname();
            }
        }
        sort($files);
        foreach ($files as $file) {
            $src = (string) file_get_contents($file);
            if (!preg_match('~final class (\w+)~', $src, $class)) {
                continue;
            }
            preg_match_all('~Abuser stor(?:y|ies):(.*?)\*/~su', $src, $mentions);
            $ids = [];
            foreach ($mentions[1] as $text) {
                preg_match_all('/[a-z0-9]+(?:-[a-z0-9]+)+/', $text, $words);
                $ids = array_merge($ids, array_intersect($words[0], $known));
            }
            foreach (array_unique($ids) as $id) {
                $out[$id][] = ['file' => substr($file, strlen($root) + 1), 'class' => $class[1]];
            }
        }
        return $out;
    }

    private static function rank(string $severity): int
    {
        return ['low' => 0, 'medium' => 1, 'elevated' => 2, 'high' => 3, 'critical' => 4][$severity] ?? 0;
    }

    /** @return array<mixed> */
    private static function arr(mixed $v): array
    {
        return is_array($v) ? $v : [];
    }

    /** @return list<string> */
    private static function strs(mixed $v): array
    {
        return array_values(array_map(static fn (mixed $x): string => is_scalar($x) ? (string) $x : '', self::list($v)));
    }

    /** @return list<mixed> */
    private static function list(mixed $v): array
    {
        return is_array($v) ? array_values($v) : [];
    }

    private static function s(mixed $a, string $k): string
    {
        return is_array($a) && is_scalar($a[$k] ?? null) ? (string) $a[$k] : '';
    }
}
