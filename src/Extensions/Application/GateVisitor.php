<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

use PhpParser\{Node, NodeVisitorAbstract};

/** Обходчик AST для StaticGate (правила allowlist). */
final class GateVisitor extends NodeVisitorAbstract
{
    /** @var list<GateViolation> */
    public array $violations = [];
    public bool $sawNamespace = false;

    public function __construct(private readonly string $path, private readonly string $ns)
    {
    }

    public function enterNode(Node $node): null
    {
        $deny = fn (string $rule) => $this->violations[] = new GateViolation($this->path, $node->getStartLine(), $rule);

        match (true) {
            $node instanceof Node\Stmt\Namespace_ => $this->namespace($node, $deny),
            $node instanceof Node\Expr\Eval_, $node instanceof Node\Expr\Include_ => $deny('eval/include is forbidden'),
            $node instanceof Node\Expr\ShellExec => $deny('Backtick shell execution is forbidden'),
            $node instanceof Node\Stmt\Echo_, $node instanceof Node\Expr\Print_, $node instanceof Node\Stmt\InlineHTML => $deny('Direct output is forbidden (return strings instead)'),
            $node instanceof Node\Expr\Exit_ => $deny('exit/die is forbidden'),
            $node instanceof Node\Stmt\Global_ => $deny('global is forbidden'),
            $node instanceof Node\Stmt\Goto_, $node instanceof Node\Stmt\HaltCompiler => $deny('goto/__halt_compiler is forbidden'),
            $node instanceof Node\Stmt\Function_ => $deny('Top-level functions are forbidden (use methods)'),
            $node instanceof Node\Stmt\Declare_ => $this->declare($node, $deny),
            $node instanceof Node\Scalar\MagicConst => $deny('Magic constants are forbidden'),
            $node instanceof Node\Expr\Cast\Array_, $node instanceof Node\Expr\Cast\Object_ => $deny('Array/object casts are forbidden'),
            $node instanceof Node\Expr\Variable => $this->variable($node, $deny),
            $node instanceof Node\Expr\FuncCall => $this->funcCall($node, $deny),
            $node instanceof Node\Expr\MethodCall, $node instanceof Node\Expr\NullsafeMethodCall => $this->method($node->name, $deny),
            $node instanceof Node\Expr\StaticCall => $this->staticCall($node, $deny),
            $node instanceof Node\Expr\PropertyFetch, $node instanceof Node\Expr\NullsafePropertyFetch => $node->name instanceof Node\Identifier ? null : $deny('Dynamic property names are forbidden'),
            $node instanceof Node\Expr\StaticPropertyFetch => $this->staticProperty($node, $deny),
            $node instanceof Node\Expr\ClassConstFetch => $this->classRef($node->class, $deny, false),
            $node instanceof Node\Expr\New_ => $this->classRef($node->class, $deny, true),
            $node instanceof Node\Expr\Instanceof_ => $this->classRef($node->class, $deny, false),
            $node instanceof Node\Stmt\Class_ => $this->classDecl($node, $deny),
            $node instanceof Node\Stmt\Interface_ => array_map(fn ($n) => $this->name($n, $deny), $node->extends),
            $node instanceof Node\Stmt\TraitUse => array_map(fn ($n) => $this->name($n, $deny), $node->traits),
            $node instanceof Node\Stmt\Catch_ => array_map(fn ($n) => $this->name($n, $deny), $node->types),
            default => null,
        };
        return null;
    }

    private function namespace(Node\Stmt\Namespace_ $n, \Closure $deny): void
    {
        $this->sawNamespace = true;
        if ($n->name === null || $n->name->toString() !== $this->ns) {
            $deny("Namespace must be {$this->ns}");
        }
    }

    private function declare(Node\Stmt\Declare_ $n, \Closure $deny): void
    {
        foreach ($n->declares as $d) {
            if ($d->key->toString() !== 'strict_types') {
                $deny('Only declare(strict_types=1) is allowed');
            }
        }
    }

    private function variable(Node\Expr\Variable $v, \Closure $deny): void
    {
        if (!is_string($v->name)) {
            $deny('Variable variables are forbidden');
        } elseif (in_array($v->name, ['GLOBALS', '_SERVER', '_GET', '_POST', '_FILES', '_COOKIE', '_SESSION', '_REQUEST', '_ENV', 'http_response_header', 'argv', 'argc'], true)) {
            $deny('Superglobals are forbidden');
        }
    }

    private function funcCall(Node\Expr\FuncCall $call, \Closure $deny): void
    {
        if (!$call->name instanceof Node\Name) {
            $deny('Dynamic function calls are forbidden');
            return;
        }
        // NameResolver помечает неквалифицированные вызовы; берём последний сегмент только для глобальных имён.
        $name = strtolower($call->name->getAttribute('namespacedName') !== null || $call->name->isUnqualified()
            ? $call->name->getLast()
            : ltrim($call->name->toString(), '\\'));
        if (!$call->name->isUnqualified() && !$call->name->isFullyQualified()) {
            $deny('Qualified function calls are forbidden');
            return;
        }
        if ($call->name->isFullyQualified() && str_contains(ltrim($call->name->toString(), '\\'), '\\')) {
            $deny('Namespaced function calls are forbidden');
            return;
        }
        if (array_key_exists($name, ['array_map' => 0, 'array_filter' => 1, 'usort' => 1, 'uasort' => 1, 'preg_replace_callback' => 1])) {
            $idx = ['array_map' => 0, 'array_filter' => 1, 'usort' => 1, 'uasort' => 1, 'preg_replace_callback' => 1][$name];
            $arg = $call->args[$idx] ?? null;
            if (!$arg instanceof Node\Arg || $arg->unpack || $arg->name !== null
                || !($arg->value instanceof Node\Expr\Closure || $arg->value instanceof Node\Expr\ArrowFunction)) {
                $deny("{$name}() requires a closure literal as the callback");
            }
            return;
        }
        if (!in_array($name, StaticGateAllowlist::FUNCTIONS, true)) {
            $deny("Function {$name}() is not allowed");
            return;
        }
        foreach ($call->args as $arg) {
            if ($arg instanceof Node\VariadicPlaceholder) {
                $deny('First-class callable syntax is forbidden');
            }
        }
    }

    private function method(Node $name, \Closure $deny): void
    {
        if (!$name instanceof Node\Identifier) {
            $deny('Dynamic method names are forbidden');
        } elseif (in_array($name->toLowerString(), ['bind', 'bindto', 'call', 'fromcallable', 'gettrace', 'gettraceasstring', '__construct', '__destruct', '__wakeup', '__unserialize', '__set_state'], true)) {
            $deny("Method {$name->toString()}() is forbidden");
        }
    }

    private function staticProperty(Node\Expr\StaticPropertyFetch $fetch, \Closure $deny): void
    {
        $this->classRef($fetch->class, $deny, false);
        if (!$fetch->name instanceof Node\VarLikeIdentifier) {
            $deny('Dynamic property names are forbidden');
        }
    }

    private function staticCall(Node\Expr\StaticCall $call, \Closure $deny): void
    {
        $this->classRef($call->class, $deny, false);
        $this->method($call->name, $deny);
    }

    private function classDecl(Node\Stmt\Class_ $c, \Closure $deny): void
    {
        if ($c->extends !== null) {
            $this->name($c->extends, $deny);
        }
        foreach ($c->implements as $i) {
            $this->name($i, $deny);
        }
    }

    private function classRef(Node $class, \Closure $deny, bool $instantiate): null
    {
        if ($class instanceof Node\Stmt\Class_) {
            return null; // анонимный класс проверяется в classDecl
        }
        if (!$class instanceof Node\Name) {
            $deny('Dynamic class names are forbidden');
            return null;
        }
        if (in_array($class->toLowerString(), ['self', 'static', 'parent'], true)) {
            return null;
        }
        $this->name($class, $deny, $instantiate);
        return null;
    }

    private function name(Node\Name $name, \Closure $deny, bool $instantiate = false): void
    {
        $fq = ltrim($name->toString(), '\\');
        $lower = strtolower($fq);
        $own = str_starts_with($fq, $this->ns . '\\');
        $api = str_starts_with($fq, StaticGate::API_NAMESPACE);
        $builtin = in_array($lower, $instantiate ? StaticGateAllowlist::INSTANTIABLE : StaticGateAllowlist::CLASSES, true);
        if (!$own && !$api && !$builtin) {
            $deny("Class {$fq} is not allowed");
        }
    }
}
