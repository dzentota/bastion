<?php // threat-model/structure.php — Bounded context: Page tree, menu, rich blocks (roadmap, release 4)
declare(strict_types=1);

use HybridTM\DSL\{AbuseCase, ThreatModel};

return static function (ThreatModel $model): void {
    $s = new AbuseCase('page-tree-cycle', 'Hang page rendering with a cyclic or very deep page tree');
    $s->asA = 'author';
    $s->iWant = 'make a page its own ancestor or nest pages without limit';
    $s->soThat = 'breadcrumb and navigation queries loop or explode for every visitor';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app', 'db'];
    $s->requiredCwes = ['CWE-835'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('trojan-source', 'Publish code samples that read differently than they run');
    $s->asA = 'malicious author or contributor';
    $s->iWant = 'put bidirectional control characters into a code block of the documentation';
    $s->soThat = 'readers copy commands or code that do something other than what they see';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-1007'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('table-bomb', 'Exhaust resources with huge tables');
    $s->asA = 'author';
    $s->iWant = 'save a table with thousands of rows and columns';
    $s->soThat = 'every page view renders a multi-megabyte table';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-400'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('menu-tamper', 'Change the site menu without the right to publish');
    $s->asA = 'author';
    $s->iWant = 'add, reorder or remove menu items, or put another language\'s or a post\'s link into the menu';
    $s->soThat = 'redirect visitors or hide sections of the site';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-285', 'CWE-20'];
    $model->addAbuseCase($s);
};
