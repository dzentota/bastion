<?php
declare(strict_types=1);

namespace Bastion\Extensions\Application;

/** Allowlist Static Gate в одном месте — чтобы изменения были видны в ревью. */
final class StaticGateAllowlist
{
    public const FUNCTIONS = [
        'strlen', 'mb_strlen', 'mb_substr', 'mb_strtolower', 'mb_strtoupper', 'mb_str_pad', 'strtolower', 'strtoupper',
        'ucfirst', 'lcfirst', 'ucwords', 'trim', 'ltrim', 'rtrim', 'str_contains', 'str_starts_with', 'str_ends_with',
        'str_replace', 'str_pad', 'str_repeat', 'substr', 'strpos', 'strrpos', 'sprintf', 'number_format',
        'implode', 'explode', 'count', 'array_slice', 'array_merge', 'array_keys', 'array_values', 'in_array',
        'array_key_exists', 'array_reverse', 'array_unique', 'array_sum', 'array_is_list', 'min', 'max', 'abs', 'round',
        'floor', 'ceil', 'intdiv', 'is_string', 'is_int', 'is_float', 'is_array', 'is_bool', 'is_null', 'intval',
        'strval', 'floatval', 'json_encode', 'preg_match', 'preg_replace', 'preg_split', 'preg_quote', 'date', 'gmdate',
    ];

    public const CLASSES = ['closure', 'stringable', 'invalidargumentexception', 'runtimeexception', 'logicexception', 'domainexception'];

    public const INSTANTIABLE = ['invalidargumentexception', 'runtimeexception', 'logicexception', 'domainexception'];
}
