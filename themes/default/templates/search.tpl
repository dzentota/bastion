{% include "partials/head" %}
<article class="prose">
  <h1>{{ t.search_title }}</h1>
  <form method="get" action="{{ site.home | url }}/search" class="search-page" role="search">
    <label for="q-page" class="visually-hidden">{{ t.search_label }}</label>
    <input id="q-page" name="q" type="search" value="{{ site.query | attr }}" maxlength="200" autocomplete="off">
    <button>{{ t.search_button }}</button>
  </form>
  {% if too_long %}<p class="error" role="alert">{{ t.search_too_long }}</p>{% endif %}
  {% if results %}<ol class="search-results">{% each results as r %}<li><a href="{{ r.url | url }}">{{ r.title }}</a><p>{{ r.snippet }}</p></li>{% endeach %}</ol>{% else %}{% if searched %}<p>{{ t.search_nothing }}</p>{% endif %}{% endif %}
</article>
{% include "partials/foot" %}
