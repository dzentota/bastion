{% include "partials/head" %}
<h1>{{ term.kind }}: {{ term.name }}</h1>
{% each posts as p %}
<article class="summary">
  <h2><a href="{{ p.url | url }}">{{ p.title }}</a></h2>
  <time>{{ p.date }}</time>
</article>
{% endeach %}
{% if not posts %}<p>Nothing published here yet.</p>{% endif %}
<nav class="pager">{% if prev %}<a href="{{ prev | url }}">← Newer</a>{% endif %} {% if next %}<a href="{{ next | url }}">Older →</a>{% endif %}</nav>
{% include "partials/foot" %}
