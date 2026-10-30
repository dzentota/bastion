<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use PhpParser\{Node, NodeTraverser, NodeVisitorAbstract, ParserFactory};
use PhpParser\Error as ParseError;
use PhpParser\NodeVisitor\NameResolver;

/**
 * Static Gate расширений (ADR-0012). Работает по allowlist: разрешено только явно перечисленное.
 *
 * Расширение может: объявлять классы/интерфейсы/enum в своём пространстве имён, вызывать чистые
 * функции из ALLOWED_FUNCTIONS, создавать и вызывать только свои классы и классы Bastion\Extension\Api.
 * Не может: eval/include/backticks/echo, динамические вызовы и имена, суперглобальные переменные,
 * магические константы путей, приведение объектов к массивам, перепривязку замыканий,
 * получение трейсов исключений, обращение к любым другим классам (PDO, Reflection, SplFileObject…).
 *
 * Это граница политики, а не песочница: она надёжна, пока парсер видит весь исполняемый код
 * (поэтому из пакета исполняются только .php-файлы, прошедшие гейт, и только они).
 */
#[AssetId('bastion-app')]
#[AbuserStory('malicious-extension')]
#[Mitigation(cwe: 'CWE-506', description: 'Every PHP file of a package is parsed and checked against an allowlist of syntax, functions and classes before installation; no I/O, network, process or reflection primitives are reachable')]
#[AbuserStory('extension-static-gate-bypass')]
#[Mitigation(cwe: 'CWE-184', description: 'Allowlist (not denylist): only listed functions/classes; dynamic calls, string callables, variable variables, closure rebinding, object-to-array casts and exception traces are rejected')]
#[AbuserStory('capability-overreach')]
#[Mitigation(cwe: 'CWE-269', description: 'Extensions can only name their own classes and Bastion\\Extension\\Api; core services are reachable solely through capability-checked facades')]
final class StaticGate
{
    public const API_NAMESPACE = 'Bastion\\Extension\\Api\\';







    /**
     * @param array<string, string> $files относительный путь => исходник (.php)
     * @return list<GateViolation>
     */
    public function check(array $files, string $namespace): array
    {
        $violations = [];
        $parser = (new ParserFactory())->createForHostVersion();
        foreach ($files as $path => $code) {
            try {
                $ast = $parser->parse($code) ?? [];
            } catch (ParseError $e) {
                $violations[] = new GateViolation($path, $e->getStartLine(), 'Parse error');
                continue;
            }
            $visitor = $this->visitor($path, rtrim($namespace, '\\'));
            $traverser = new NodeTraverser(new NameResolver(), $visitor);
            $traverser->traverse($ast);
            array_push($violations, ...$visitor->violations);
            if (!$visitor->sawNamespace && $ast !== []) {
                $violations[] = new GateViolation($path, 1, "Code must be inside namespace {$namespace}");
            }
        }
        return $violations;
    }

    private function visitor(string $path, string $ns): GateVisitor
    {
        return new GateVisitor($path, $ns);
    }
}
