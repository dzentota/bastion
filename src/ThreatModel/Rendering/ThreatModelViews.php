<?php
declare(strict_types=1);

namespace Bastion\ThreatModel\Rendering;

use Bastion\ThreatModel\Domain\ThreatModelData;

/**
 * Представления модели угроз для блока «Модель угроз»: сводка, матрица покрытия, находки
 * анализатора, DFD. Разметку задаёт только этот класс; данные модели экранируются.
 * Статус и серьёзность различаются знаком, а не только цветом.
 */
final class ThreatModelViews
{
    public const VIEWS = ['overview', 'matrix', 'findings', 'dfd'];

    private const STATUS_MARK = ['covered' => '✓', 'partial' => '◐', 'uncovered' => '✕', 'backlog' => '○'];
    private const SEVERITY_MARK = ['critical' => '▲▲', 'high' => '▲', 'elevated' => '◆', 'medium' => '●', 'low' => '○'];

    /** @param array<string, string> $t строки темы на языке страницы */
    public function __construct(private readonly array $t, private readonly string $lang)
    {
    }

    public function render(string $view, ?ThreatModelData $m): string
    {
        if ($m === null) {
            return '<p class="tm-missing">' . $this->e($this->t['tm_unavailable'] ?? 'The threat model export is not available on this site.') . '</p>';
        }
        return match ($view) {
            'overview' => $this->overview($m),
            'matrix' => $this->matrix($m),
            'findings' => $this->findings($m),
            'dfd' => $this->dfd($m),
            default => '',
        };
    }

    private function overview(ThreatModelData $m): string
    {
        $byStatus = array_count_values(array_column($m->stories, 'status'));
        $open = array_values(array_filter($m->findings, static fn (array $f) => $f['decision'] === null));
        $bySeverity = array_count_values(array_column($open, 'severity'));
        $tested = count(array_filter($m->stories, static fn (array $s) => $s['tests'] !== []));
        $mitigations = array_sum(array_map(static fn (array $s) => count($s['mitigations']), $m->stories));
        $sev = [];
        foreach (array_reverse(ThreatModelData::SEVERITIES) as $s) {
            if (($bySeverity[$s] ?? 0) > 0) {
                $sev[] = $this->mark(self::SEVERITY_MARK[$s], 'sev-' . $s) . ' ' . $bySeverity[$s] . ' ' . $this->e($this->t['sev_' . $s] ?? $s);
            }
        }
        $rows = [
            [$this->t['tm_stories'] ?? 'Abuser stories', (string) count($m->stories),
                $this->mark('✓', 'st-covered') . ' ' . ($byStatus['covered'] ?? 0) . ' ' . $this->e($this->t['st_covered'] ?? 'covered')
                . (($byStatus['backlog'] ?? 0) > 0 ? ', ' . $byStatus['backlog'] . ' ' . $this->e($this->t['st_backlog'] ?? 'in backlog') : '')],
            [$this->t['tm_mitigations'] ?? 'Mitigations in code', (string) $mitigations, ''],
            [$this->t['tm_tested'] ?? 'Stories with attack tests', $tested . ' / ' . count($m->stories), ''],
            [$this->t['tm_flows'] ?? 'Data flows', (string) count($m->flows), ''],
            [$this->t['tm_findings_open'] ?? 'Open analyzer findings', (string) count($open), implode(', ', $sev)],
            [$this->t['tm_findings_decided'] ?? 'Findings with a recorded decision', (string) (count($m->findings) - count($open)), ''],
        ];
        $html = '<table class="tm-overview"><tbody>';
        foreach ($rows as [$label, $value, $detail]) {
            $html .= '<tr><th scope="row">' . $this->e($label) . '</th><td class="num">' . $this->e($value) . '</td><td>' . $detail . '</td></tr>';
        }
        return $html . '</tbody></table><p class="tm-source">' . $this->e($this->t['tm_input_hash'] ?? 'Model input hash') . ' <code>' . $this->e(substr($m->inputHash, 0, 16)) . '</code></p>';
    }

    private function matrix(ThreatModelData $m): string
    {
        $stories = $m->stories;
        usort($stories, static fn (array $a, array $b) => [$a['assets'][0] ?? '', $a['id']] <=> [$b['assets'][0] ?? '', $b['id']]);
        $html = '<div class="table"><table class="tm-matrix"><thead><tr><th>' . $this->e($this->t['tm_story'] ?? 'Abuser story') . '</th><th>'
            . $this->e($this->t['tm_assets'] ?? 'Assets') . '</th><th>CWE</th><th class="num">' . $this->e($this->t['tm_mitigations_short'] ?? 'Mitigations')
            . '</th><th class="num">' . $this->e($this->t['tm_tests_short'] ?? 'Tests') . '</th><th>' . $this->e($this->t['tm_status'] ?? 'Status') . '</th></tr></thead><tbody>';
        foreach ($stories as $s) {
            $html .= '<tr><td><a href="' . $this->e($this->storyUrl($s['id'])) . '">' . $this->e($s['title']) . '</a><br><code>' . $this->e($s['id']) . '</code></td>'
                . '<td>' . $this->e(implode(', ', array_map($m->componentName(...), $s['assets']))) . '</td>'
                . '<td>' . $this->cwes($s['requiredCwes']) . '</td>'
                . '<td class="num">' . count($s['mitigations']) . '</td><td class="num">' . count($s['tests']) . '</td>'
                . '<td>' . $this->status($s['status']) . '</td></tr>';
        }
        return $html . '</tbody></table></div>';
    }

    private function findings(ThreatModelData $m): string
    {
        $html = '<div class="table"><table class="tm-findings"><thead><tr><th>' . $this->e($this->t['tm_severity'] ?? 'Severity') . '</th><th>'
            . $this->e($this->t['tm_finding'] ?? 'Finding') . '</th><th>' . $this->e($this->t['tm_subject'] ?? 'Where') . '</th><th>'
            . $this->e($this->t['tm_decision'] ?? 'Decision') . '</th></tr></thead><tbody>';
        foreach ($m->findings as $f) {
            $decision = $f['decision'] === null
                ? '<strong>' . $this->e($this->t['tm_open'] ?? 'open') . '</strong>'
                : $this->e($this->t['decision_' . str_replace('-', '_', $f['decision']['status'])] ?? $f['decision']['status']) . '<br><span class="hint">' . $this->e($f['decision']['justification']) . '</span>';
            $html .= '<tr' . ($f['decision'] !== null ? ' class="tm-decided"' : '') . '><td>' . $this->severity($f['severity']) . '</td>'
                . '<td><strong>' . $this->e($f['title']) . '</strong><br><span class="hint">' . $this->e($f['description']) . '</span>'
                . ($f['cwe'] !== [] ? '<br>' . $this->cwes($f['cwe']) : '') . '</td>'
                . '<td><code>' . $this->e($f['subject']) . '</code></td><td>' . $decision . '</td></tr>';
        }
        return $html . '</tbody></table></div>';
    }

    private function dfd(ThreatModelData $m): string
    {
        $r = DfdSvg::render($m, $this->t['tm_dfd_title'] ?? 'Data-flow diagram');
        $rows = '';
        foreach ($m->flows as $f) {
            $n = $r['numbers'][$f['id']] ?? null;
            if ($n === null) {
                continue;
            }
            $data = array_map(fn (string $id) => $m->dataAssets[$id] ?? $id, array_values(array_unique(array_merge($f['sent'], $f['received']))));
            $rows .= '<tr><td class="num">' . $n . '</td><td>' . $this->e($m->componentName($f['from'])) . ' → ' . $this->e($m->componentName($f['to'])) . '<br><span class="hint">' . $this->e($f['description']) . '</span></td>'
                . '<td><code>' . $this->e($f['protocol']) . '</code></td><td><code>' . $this->e($f['authentication']) . '</code></td><td>' . $this->e(implode(', ', $data)) . '</td></tr>';
        }
        return '<figure class="tm-dfd">' . $r['svg'] . '<figcaption><a href="' . $this->e('/' . $this->lang . '/threats#s1') . '">'
            . $this->e($this->t['tm_dfd_full'] ?? 'Open the full-size diagram') . '</a></figcaption></figure>'
            . '<div class="table"><table class="tm-flows"><caption>' . $this->e($this->t['tm_flows_caption'] ?? 'Flows in the diagram') . '</caption><thead><tr><th class="num">#</th><th>'
            . $this->e($this->t['tm_flow'] ?? 'Flow') . '</th><th>' . $this->e($this->t['tm_protocol'] ?? 'Protocol') . '</th><th>' . $this->e($this->t['tm_authn'] ?? 'Authentication') . '</th><th>'
            . $this->e($this->t['tm_data'] ?? 'Data') . '</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';
    }

    public function storyUrl(string $id): string
    {
        return '/' . $this->lang . '/threats/' . $id;
    }

    /** @param list<string> $cwes */
    private function cwes(array $cwes): string
    {
        return implode(' ', array_map(fn (string $c) => '<a class="cwe" href="https://cwe.mitre.org/data/definitions/' . $this->e(substr($c, 4)) . '.html" rel="noopener noreferrer">' . $this->e($c) . '</a>', $cwes));
    }

    public function status(string $status): string
    {
        return $this->mark(self::STATUS_MARK[$status] ?? '?', 'st-' . $status) . ' ' . $this->e($this->t['st_' . $status] ?? $status);
    }

    public function severity(string $severity): string
    {
        return $this->mark(self::SEVERITY_MARK[$severity] ?? '?', 'sev-' . $severity) . ' ' . $this->e($this->t['sev_' . $severity] ?? $severity);
    }

    private function mark(string $glyph, string $class): string
    {
        return '<span class="tm-mark ' . $this->e($class) . '" aria-hidden="true">' . $glyph . '</span>';
    }

    private function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
