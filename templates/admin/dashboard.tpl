{% include "partials/head" %}
{% each notices as n %}
<div class="notice notice-{{ n.level | attr }}" role="status"><strong>{{ n.title }}</strong><p>{{ n.detail }}</p></div>
{% endeach %}
<div class="page-head">
  <h1>{{ t.content }}</h1>
  <p class="actions"><a class="button" href="/admin/entries/new">{{ t.new_post }}</a> <a class="button secondary" href="/admin/entries/new?type=page">{{ t.new_page }}</a></p>
</div>
<table>
  <thead><tr><th>{{ t.title }}</th><th>{{ t.language }}</th><th>{{ t.type }}</th><th>{{ t.status }}</th><th></th></tr></thead>
  <tbody>
  {% each entries as e %}
    <tr>
      <td><a href="/admin/entries/{{ e.id | attr }}/edit">{{ e.title }}</a></td>
      <td><code>{{ e.lang }}</code></td>
      <td>{% if e.is_page %}{{ t.type_page }}{% else %}{{ t.type_post }}{% endif %}</td>
      <td>{% if e.published %}{{ t.status_published }}{% else %}{{ t.status_draft }}{% endif %}</td>
      <td>{% if e.published %}<a href="{{ e.url | url }}">{{ t.view }}</a>{% endif %}</td>
    </tr>
  {% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
