<?php
declare(strict_types=1);

namespace Bastion\Extensions\Domain;

/** extension.json, распарсенный целиком в доменные примитивы (правило 3). */
final class Manifest
{
    /** @param list<ExtCapability> $capabilities */
    public function __construct(
        public readonly ExtensionName $name,
        public readonly ExtensionVersion $version,
        public readonly PublisherKey $publisher,
        public readonly array $capabilities,
        public readonly string $entryClass,
    ) {
    }

    /** @throws InvalidPackage */
    public static function parse(string $json): self
    {
        try {
            $d = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidPackage('extension.json is not valid JSON');
        }
        if (!is_array($d) || array_diff(array_keys($d), ['name', 'version', 'publisher_key', 'capabilities', 'entry', 'description']) !== []) {
            throw new InvalidPackage('extension.json has unknown fields');
        }
        $caps = [];
        foreach (is_array($d['capabilities'] ?? null) ? $d['capabilities'] : [] as $c) {
            $caps[] = is_string($c) ? (ExtCapability::tryFrom($c) ?? throw new InvalidPackage("Unknown capability {$c}")) : throw new InvalidPackage('Bad capability');
        }
        $entry = $d['entry'] ?? null;
        if (!is_string($entry) || !preg_match('/^[A-Z][A-Za-z0-9]{0,63}$/', $entry)) {
            throw new InvalidPackage('entry must be a class name like Plugin');
        }
        return new self(
            ExtensionName::tryParse($d['name'] ?? null, $n) ? $n : throw new InvalidPackage('Invalid name'),
            ExtensionVersion::tryParse($d['version'] ?? null, $v) ? $v : throw new InvalidPackage('Invalid version'),
            PublisherKey::tryParse($d['publisher_key'] ?? null, $k) ? $k : throw new InvalidPackage('Invalid publisher_key'),
            array_values(array_unique($caps, SORT_REGULAR)),
            $entry,
        );
    }

    public function entryFqcn(): string
    {
        return $this->name->namespace() . '\\' . $this->entryClass;
    }

    /** @return list<string> */
    public function capabilityValues(): array
    {
        return array_map(static fn (ExtCapability $c) => $c->value, $this->capabilities);
    }
}
