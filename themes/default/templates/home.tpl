{% include "partials/head" %}
{% each posts as p %}
<article class="summary">
  <h2><a href="{{ p.url | url }}">{{ p.title }}</a></h2>
  <time>{{ p.date }}</time>
</article>
{% endeach %}
{% if not posts %}<p>{{ t.nothing_published }}</p>{% endif %}
{% include "partials/foot" %}
