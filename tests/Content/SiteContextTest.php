<?php
declare(strict_types=1);

namespace Bastion\Tests\Content;

use Bastion\Http\SiteContext;
use PHPUnit\Framework\TestCase;

final class SiteContextTest extends TestCase
{
    public function testIssuesUrlIsHttpsOnly(): void
    {
        self::assertSame('https://github.com/acme/bastion/issues', SiteContext::issuesUrl('https://github.com/acme/bastion/issues'));
        foreach (['http://github.com/x', 'javascript:alert(1)', 'https://user:pass@github.com/x', 'https://github.com/x?a=1', 'https://github.com/x#y', '//github.com', 42, null] as $bad) {
            self::assertNull(SiteContext::issuesUrl($bad), var_export($bad, true));
        }
    }
}
