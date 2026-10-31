{% include "partials/head" %}
<h1>{% if term.is_category %}{{ t.category }}{% else %}{{ t.tag }}{% endif %}: {{ term.name }}</h1>
{% each posts as p %}
<article class="summary">
  <h2><a href="{{ p.url | url }}">{{ p.title }}</a></h2>
  <time>{{ p.date }}</time>
</article>
{% endeach %}
{% if not posts %}<p>{{ t.nothing_published_here }}</p>{% endif %}
<nav class="pager">{% if prev %}<a href="{{ prev | url }}">← {{ t.newer }}</a>{% endif %} {% if next %}<a href="{{ next | url }}">{{ t.older }} →</a>{% endif %}</nav>
{% include "partials/foot" %}
