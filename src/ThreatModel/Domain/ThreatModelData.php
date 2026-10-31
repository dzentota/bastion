<?php
declare(strict_types=1);

namespace Bastion\ThreatModel\Domain;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};

/**
 * Экспорт модели угроз (bin/threat-model-export, ADR-0023), разобранный строго: файл —
 * недоверенный вход (правило 4). Идентификаторы — по шаблону, тексты — с ограничением длины,
 * перечисления — из закрытых списков; что не прошло проверку — исключение, а не «как есть».
 */
#[AssetId('bastion-app')]
#[AbuserStory('threat-model-export-tamper')]
#[Mitigation(cwe: 'CWE-20', description: 'The exported JSON is parsed strictly: format/version checked, ids by pattern, bounded strings, enumerations from closed lists; malformed data is rejected as a whole')]
final class ThreatModelData
{
    public const MAX_BYTES = 2_000_000;
    public const STATUSES = ['covered', 'partial', 'uncovered', 'backlog'];
    public const SEVERITIES = ['low', 'medium', 'elevated', 'high', 'critical'];

    /**
     * @param list<array{id: string, name: string, type: string}> $boundaries
     * @param list<array{id: string, name: string, type: string, technology: string, internet: bool, actor: bool, boundary: ?string}> $components
     * @param list<array{id: string, from: string, to: string, description: string, protocol: string, authentication: string, authorization: string, sent: list<string>, received: list<string>}> $flows
     * @param array<string, string> $dataAssets id => name
     * @param list<array{id: string, title: string, asA: string, iWant: string, soThat: string, actor: string, assets: list<string>, requiredCwes: list<string>, missingCwes: list<string>, status: string, mitigations: list<array{cwe: string, description: string, file: string, line: int, symbol: string}>, tests: list<array{file: string, class: string}>}> $stories
     * @param list<array{id: string, threat: string, title: string, description: string, severity: string, subject: string, stride: list<string>, cwe: list<string>, decision: ?array{status: string, justification: string}}> $findings
     */
    private function __construct(
        public readonly string $inputHash,
        public readonly array $boundaries,
        public readonly array $components,
        public readonly array $flows,
        public readonly array $dataAssets,
        public readonly array $stories,
        public readonly array $findings,
    ) {
    }

    /** @throws InvalidThreatModel */
    public static function fromJson(string $json): self
    {
        if (strlen($json) > self::MAX_BYTES) {
            throw new InvalidThreatModel('too large');
        }
        try {
            $d = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidThreatModel('malformed JSON');
        }
        if (!is_array($d) || ($d['format'] ?? null) !== 'bastion-threat-model' || ($d['version'] ?? null) !== 1) {
            throw new InvalidThreatModel('unknown format');
        }
        $boundaries = self::each($d, 'boundaries', 50, static fn (array $b) => ['id' => self::id($b, 'id'), 'name' => self::text($b, 'name', 200), 'type' => self::id($b, 'type')]);
        $bIds = array_column($boundaries, 'id');
        $components = self::each($d, 'components', 200, static function (array $c) use ($bIds): array {
            $boundary = $c['boundary'] ?? null;
            if ($boundary !== null && !in_array($boundary, $bIds, true)) {
                throw new InvalidThreatModel('component boundary');
            }
            return ['id' => self::id($c, 'id'), 'name' => self::text($c, 'name', 200), 'type' => self::id($c, 'type'), 'technology' => self::id($c, 'technology', true),
                'internet' => ($c['internet'] ?? false) === true, 'actor' => ($c['actor'] ?? false) === true, 'boundary' => is_string($boundary) ? $boundary : null];
        });
        $cIds = array_column($components, 'id');
        $flows = self::each($d, 'flows', 500, static function (array $f) use ($cIds): array {
            $flow = ['id' => self::id($f, 'id'), 'from' => self::id($f, 'from'), 'to' => self::id($f, 'to'), 'description' => self::text($f, 'description', 300, true),
                'protocol' => self::id($f, 'protocol'), 'authentication' => self::id($f, 'authentication'), 'authorization' => self::id($f, 'authorization'),
                'sent' => self::ids($f, 'sent'), 'received' => self::ids($f, 'received')];
            if (!in_array($flow['from'], $cIds, true) || !in_array($flow['to'], $cIds, true)) {
                throw new InvalidThreatModel('flow endpoint');
            }
            return $flow;
        });
        $dataAssets = [];
        foreach (self::each($d, 'dataAssets', 200, static fn (array $a) => [self::id($a, 'id'), self::text($a, 'name', 200)]) as [$id, $name]) {
            $dataAssets[$id] = $name;
        }
        $stories = self::each($d, 'stories', 1000, static function (array $s): array {
            $status = self::id($s, 'status');
            in_array($status, self::STATUSES, true) || throw new InvalidThreatModel('story status');
            return [
                'id' => self::id($s, 'id'), 'title' => self::text($s, 'title', 300), 'asA' => self::text($s, 'asA', 300, true),
                'iWant' => self::text($s, 'iWant', 600, true), 'soThat' => self::text($s, 'soThat', 600, true), 'actor' => self::id($s, 'actor', true),
                'assets' => self::ids($s, 'assets'), 'requiredCwes' => self::cwes($s, 'requiredCwes'), 'missingCwes' => self::cwes($s, 'missingCwes'), 'status' => $status,
                'mitigations' => self::each($s, 'mitigations', 50, static fn (array $m) => ['cwe' => self::cwe($m['cwe'] ?? null), 'description' => self::text($m, 'description', 600),
                    'file' => self::path($m, 'file'), 'line' => is_int($m['line'] ?? null) && $m['line'] >= 0 ? $m['line'] : 0, 'symbol' => self::text($m, 'symbol', 200, true)]),
                'tests' => self::each($s, 'tests', 50, static fn (array $t) => ['file' => self::path($t, 'file'), 'class' => self::text($t, 'class', 200)]),
            ];
        });
        $findings = self::each($d, 'findings', 1000, static function (array $f): array {
            $severity = self::id($f, 'severity');
            in_array($severity, self::SEVERITIES, true) || throw new InvalidThreatModel('severity');
            $decision = $f['decision'] ?? null;
            return [
                'id' => self::hex($f, 'id'), 'threat' => self::text($f, 'threat', 120), 'title' => self::text($f, 'title', 300), 'description' => self::text($f, 'description', 2000, true),
                'severity' => $severity, 'subject' => self::text($f, 'subject', 200), 'stride' => self::ids($f, 'stride'), 'cwe' => self::cwes($f, 'cwe'),
                'decision' => is_array($decision) ? ['status' => self::id($decision, 'status'), 'justification' => self::text($decision, 'justification', 1000, true)] : null,
            ];
        });
        return new self(self::hex($d, 'inputHash'), $boundaries, $components, $flows, $dataAssets, $stories, $findings);
    }

    /** @return array{id: string, title: string, asA: string, iWant: string, soThat: string, actor: string, assets: list<string>, requiredCwes: list<string>, missingCwes: list<string>, status: string, mitigations: list<array{cwe: string, description: string, file: string, line: int, symbol: string}>, tests: list<array{file: string, class: string}>}|null */
    public function story(string $id): ?array
    {
        foreach ($this->stories as $s) {
            if ($s['id'] === $id) {
                return $s;
            }
        }
        return null;
    }

    public function componentName(string $id): string
    {
        foreach ($this->components as $c) {
            if ($c['id'] === $id) {
                return $c['name'];
            }
        }
        return $id;
    }

    /**
     * @template T
     * @param array<mixed> $d
     * @param callable(array<mixed>): T $map
     * @return list<T>
     */
    private static function each(array $d, string $key, int $max, callable $map): array
    {
        $list = $d[$key] ?? null;
        if (!is_array($list) || !array_is_list($list) || count($list) > $max) {
            throw new InvalidThreatModel($key);
        }
        return array_map(static fn (mixed $x) => is_array($x) ? $map($x) : throw new InvalidThreatModel($key), $list);
    }

    /** @param array<mixed> $a */
    private static function id(array $a, string $k, bool $emptyOk = false): string
    {
        $v = $a[$k] ?? null;
        if (is_string($v) && (($emptyOk && $v === '') || preg_match('/^[a-z0-9][a-z0-9._-]{0,79}$/', $v))) {
            return $v;
        }
        throw new InvalidThreatModel($k);
    }

    /** @param array<mixed> $a */
    private static function hex(array $a, string $k): string
    {
        $v = $a[$k] ?? null;
        return is_string($v) && preg_match('/^[0-9a-f]{32,64}$/', $v) ? $v : throw new InvalidThreatModel($k);
    }

    /** @param array<mixed> $a */
    private static function text(array $a, string $k, int $max, bool $emptyOk = false): string
    {
        $v = $a[$k] ?? null;
        if (!is_string($v) || !mb_check_encoding($v, 'UTF-8') || mb_strlen($v) > $max || (!$emptyOk && trim($v) === '')
            || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', $v)) {
            throw new InvalidThreatModel($k);
        }
        return $v;
    }

    /** @param array<mixed> $a */
    private static function path(array $a, string $k): string
    {
        $v = self::text($a, $k, 300, true);
        // путь внутри репозитория, только относительный
        return $v === '' || preg_match('~^(?!/)(?!.*\.\.)[A-Za-z0-9_./-]+$~', $v) ? $v : throw new InvalidThreatModel($k);
    }

    /**
     * @param array<mixed> $a
     * @return list<string>
     */
    private static function ids(array $a, string $k): array
    {
        $list = $a[$k] ?? [];
        if (!is_array($list) || count($list) > 100) {
            throw new InvalidThreatModel($k);
        }
        return array_values(array_map(static fn (mixed $v) => self::id(['v' => $v], 'v'), $list));
    }

    /**
     * @param array<mixed> $a
     * @return list<string>
     */
    private static function cwes(array $a, string $k): array
    {
        $list = $a[$k] ?? [];
        if (!is_array($list) || count($list) > 50) {
            throw new InvalidThreatModel($k);
        }
        return array_values(array_map(self::cwe(...), $list));
    }

    private static function cwe(mixed $v): string
    {
        return is_string($v) && preg_match('/^CWE-\d{1,5}$/', $v) ? $v : throw new InvalidThreatModel('cwe');
    }
}
