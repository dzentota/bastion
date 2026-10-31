{% include "partials/head" %}
<header class="bar">
  <strong>Bastion</strong>
  <span>Signed in as {{ me.name }}</span>
  <form method="post" action="/admin/logout"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="link">Sign out</button></form>
</header>
{% each notices as n %}
<div class="notice notice-{{ n.level | attr }}" role="status"><strong>{{ n.title }}</strong><p>{{ n.detail }}</p></div>
{% endeach %}
<h1>Content</h1>
<p><a class="button" href="/admin/entries/new">New post</a> <a class="button" href="/admin/entries/new?type=page">New page</a> <a href="/admin/media">Media library</a> · <a href="/admin/comments">Comments</a> · <a href="/admin/audit">Audit</a> · <a href="/admin/extensions">Extensions</a></p>
<table>
  <thead><tr><th>Title</th><th>Lang</th><th>Type</th><th>Status</th><th></th></tr></thead>
  <tbody>
  {% each entries as e %}
    <tr>
      <td><a href="/admin/entries/{{ e.id | attr }}/edit">{{ e.title }}</a></td>
      <td><code>{{ e.lang }}</code></td>
      <td>{{ e.type }}</td>
      <td>{{ e.status }}</td>
      <td>{% if e.published %}<a href="{{ e.url | url }}">View</a>{% endif %}</td>
    </tr>
  {% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
