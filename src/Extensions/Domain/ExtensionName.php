<?php
declare(strict_types=1);

namespace Bastion\Extensions\Domain;

use dzentota\TypedValue\Typed;
use dzentota\TypedValue\TypedValue;
use dzentota\TypedValue\ValidationResult;

/**
 * "vendor/name" — латиница в нижнем регистре, цифры, дефисы.
 * @implements Typed<string>
 */
final class ExtensionName implements Typed
{
    /** @use TypedValue<string> */
    use TypedValue;

    public static function validate($value): ValidationResult
    {
        $r = new ValidationResult();
        if (!is_string($value) || !preg_match('~^[a-z][a-z0-9-]{1,31}/[a-z][a-z0-9-]{1,31}$~', $value) || str_contains($value, '--')) {
            $r->addError('Extension name must be vendor/name in lowercase latin letters, digits and dashes');
        }
        return $r;
    }

    public function vendor(): string
    {
        return explode('/', (string) $this->value)[0];
    }

    public function package(): string
    {
        return explode('/', (string) $this->value)[1];
    }

    /** BastionExt\Vendor\Package — единственное пространство имён, доступное коду расширения. */
    public function namespace(): string
    {
        $studly = static fn (string $s) => str_replace(' ', '', ucwords(str_replace('-', ' ', $s)));
        return 'BastionExt\\' . $studly($this->vendor()) . '\\' . $studly($this->package());
    }

    /** Префикс helper'ов в Template DSL: acme/hello-world → acme_hello_world_ */
    public function helperPrefix(): string
    {
        return str_replace(['/', '-'], '_', (string) $this->value) . '_';
    }
}
