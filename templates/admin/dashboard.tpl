{% include "partials/head" %}
<header class="bar">
  <strong>Bastion</strong>
  <span>Signed in as {{ me.name }}</span>
  <form method="post" action="/admin/logout"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="link">Sign out</button></form>
</header>
<h1>Posts</h1>
<p><a class="button" href="/admin/entries/new">New post</a></p>
<table>
  <thead><tr><th>Title</th><th>Status</th><th></th></tr></thead>
  <tbody>
  {% each entries as e %}
    <tr>
      <td><a href="/admin/entries/{{ e.id | attr }}/edit">{{ e.title }}</a></td>
      <td>{{ e.status }}</td>
      <td>{% if e.published %}<a href="{{ e.url | url }}">View</a>{% endif %}</td>
    </tr>
  {% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
