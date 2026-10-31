{% include "partials/head" %}
<p><a href="/admin/entries/{{ entry.id | attr }}/edit">← {{ entry.title }}</a></p>
<h1>{{ t.revision_history }}</h1>
{% if intact %}<p class="ok" role="status">{{ t.revisions_intact }}</p>{% else %}<p class="errors" role="alert"><strong>{{ t.revisions_broken }}</strong> {{ t.revisions_broken_at }} {{ broken_at }}. {{ t.revisions_broken_hint }}</p>{% endif %}
<table>
  <thead><tr><th>#</th><th>{{ t.revision_time }}</th><th>{{ t.title }}</th><th>{{ t.revision_author }}</th><th></th><th></th></tr></thead>
  <tbody>
  {% each revisions as r %}<tr>
    <td>{{ r.seq }}</td>
    <td>{{ r.at }}</td>
    <td>{{ r.title }}{% if r.restored_from %} <span class="hint">({{ t.restored_from }} #{{ r.restored_from }})</span>{% endif %}</td>
    <td>{{ r.author }}</td>
    <td>{% if r.published %}<strong>{{ t.revision_live }}</strong>{% endif %}{% if r.head %} {{ t.revision_current }}{% endif %}</td>
    <td>{% if not r.head %}{% if intact %}<form method="post" action="/admin/entries/{{ entry.id | attr }}/revisions/{{ r.seq | attr }}/restore"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="link">{{ t.restore_revision }}</button></form>{% endif %}{% endif %}</td>
  </tr>{% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
