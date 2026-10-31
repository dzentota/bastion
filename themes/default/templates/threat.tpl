{% include "partials/head" %}
<article class="prose">
  <nav class="breadcrumbs" aria-label="{{ t.breadcrumbs | attr }}"><a href="{{ index | url }}">{{ t.tm_title }}</a> ›</nav>
  <h1>{{ story.title }}</h1>
  <p class="tm-story-id"><code>{{ story.id }}</code> · {{ story.status }}</p>
  <dl class="tm-story">
    <dt>{{ t.tm_as_a }}</dt><dd>{{ story.as_a }}</dd>
    <dt>{{ t.tm_i_want }}</dt><dd>{{ story.i_want }}</dd>
    <dt>{{ t.tm_so_that }}</dt><dd>{{ story.so_that }}</dd>
    <dt>{{ t.tm_actor }}</dt><dd>{{ story.actor }}</dd>
    <dt>{{ t.tm_assets }}</dt><dd>{% each story.assets as a %}<span class="tm-asset">{{ a }}</span> {% endeach %}</dd>
    <dt>{{ t.tm_required_cwes }}</dt><dd>{% each story.cwes as c %}<a class="cwe" href="{{ c.url | url }}" rel="noopener noreferrer">{{ c.id }}</a> {% endeach %}</dd>
  </dl>
  {% if story.missing %}<p class="error" role="alert">{{ t.tm_missing_cwes }} {% each story.missing as c %}<code>{{ c }}</code> {% endeach %}</p>{% endif %}
  <h2 id="s1">{{ t.tm_mitigations }}</h2>
  {% if story.mitigations %}<ul class="tm-mitigations">{% each story.mitigations as m %}<li><strong>{{ m.cwe }}</strong> — {{ m.description }}<br><code>{{ m.where }}</code>{% if m.symbol %} <span class="hint">{{ m.symbol }}</span>{% endif %}</li>{% endeach %}</ul>{% else %}<p>{{ t.tm_no_mitigations }}</p>{% endif %}
  <h2 id="s2">{{ t.tm_attack_tests }}</h2>
  {% if story.tests %}<ul class="tm-tests">{% each story.tests as x %}<li><code>{{ x.file }}</code> <span class="hint">{{ x.class }}</span></li>{% endeach %}</ul>{% else %}<p>{{ t.tm_no_tests }}</p>{% endif %}
</article>
{% include "partials/foot" %}
