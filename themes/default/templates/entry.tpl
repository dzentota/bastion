{% include "partials/head" %}
<article>
  <h1>{{ entry.title }}</h1>
  <time>{{ entry.date }}</time>
  {{ entry.body }}
</article>
{% include "partials/foot" %}
