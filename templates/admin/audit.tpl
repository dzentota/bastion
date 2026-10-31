{% include "partials/head" %}
<h1>{{ t.audit_trail }}</h1>
{% if intact %}<p class="ok" role="status">{{ t.integrity_ok_prefix }} {{ count }} {{ t.integrity_ok_suffix }}</p>{% else %}<p class="errors" role="alert"><strong>{{ t.integrity_failed }}</strong> {{ reason }}. {{ t.integrity_tampered }}</p>{% endif %}
<table>
  <thead><tr><th>#</th><th>{{ t.time }}</th><th>{{ t.action }}</th><th>{{ t.actor }}</th><th>{{ t.subject }}</th><th>{{ t.ip }}</th></tr></thead>
  <tbody>
  {% each entries as e %}<tr><td>{{ e.seq }}</td><td>{{ e.at }}</td><td>{{ e.action }}</td><td>{% if e.actor_name %}<span title="{{ e.actor | attr }}">{{ e.actor_name }}</span>{% else %}<code>{{ e.actor }}</code>{% endif %}</td><td>{% if e.subject_name %}<span title="{{ e.subject | attr }}">{{ e.subject_name }}</span>{% else %}<code>{{ e.subject }}</code>{% endif %}</td><td>{{ e.ip }}</td></tr>{% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
