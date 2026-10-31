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

    $s = new AbuseCase('vendored-asset-tamper', 'Swap a vendored font or stylesheet');
    $s->asA = 'supply-chain attacker or attacker with file write on the hosting';
    $s->iWant = 'replace a self-hosted font file with a malformed one, or load fonts from a third-party CDN';
    $s->soThat = 'exploit a font parser in visitors\' browsers, or track visitors through third-party requests';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['app-filesystem'];
    $s->requiredCwes = ['CWE-494'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('threat-model-export-tamper', 'Show a false security picture through the threat-model export');
    $s->asA = 'attacker with file write on the hosting or in the release pipeline';
    $s->iWant = 'edit build/threat-model.json so every story looks covered, or make it crash the renderer';
    $s->soThat = 'readers trust a weaker system, or the documentation site breaks';
    $s->actorId = 'malicious-publisher';
    $s->assetIds = ['bastion-app', 'app-filesystem'];
    $s->requiredCwes = ['CWE-20', 'CWE-494'];
    $model->addAbuseCase($s);

    $s = new AbuseCase('svg-injection', 'Inject script through the generated data-flow diagram');
    $s->asA = 'contributor to the threat model';
    $s->iWant = 'put markup into a component or flow name';
    $s->soThat = 'it runs as SVG or HTML in visitors\' browsers';
    $s->actorId = 'malicious-author';
    $s->assetIds = ['bastion-app'];
    $s->requiredCwes = ['CWE-79'];
    $model->addAbuseCase($s);
};
