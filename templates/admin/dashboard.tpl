{% include "partials/head" %}
<header class="bar">
  <strong>Bastion</strong>
  <span>{{ t.signed_in_as }} {{ me.name }}</span>
  {% if ui_languages %}<form method="post" action="/admin/locale" class="ui-lang"><input type="hidden" name="_token" value="{{ csrf | attr }}">{% each ui_languages as l %}{% if l.current %}<strong>{{ l.code }}</strong>{% else %}<button class="link" name="lang" value="{{ l.code | attr }}" lang="{{ l.code | attr }}">{{ l.code }}</button>{% endif %} {% endeach %}</form>{% endif %}
  <form method="post" action="/admin/logout"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="link">{{ t.sign_out }}</button></form>
</header>
{% each notices as n %}
<div class="notice notice-{{ n.level | attr }}" role="status"><strong>{{ n.title }}</strong><p>{{ n.detail }}</p></div>
{% endeach %}
<h1>{{ t.content }}</h1>
<p><a class="button" href="/admin/entries/new">{{ t.new_post }}</a> <a class="button" href="/admin/entries/new?type=page">{{ t.new_page }}</a> <a href="/admin/media">{{ t.media_library }}</a> · <a href="/admin/comments">{{ t.comments }}</a> · <a href="/admin/audit">{{ t.audit }}</a> · <a href="/admin/extensions">{{ t.extensions }}</a> · <a href="/admin/menu">{{ t.site_menu }}</a> · <a href="/admin/database">{{ t.database }}</a></p>
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
