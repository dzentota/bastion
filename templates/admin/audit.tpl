{% include "partials/head" %}
<p><a href="/admin">← Content</a></p>
<h1>Audit trail</h1>
{% if intact %}<p class="ok" role="status">Integrity verified: {{ count }} entries, chain and anchor intact.</p>{% else %}<p class="errors" role="alert"><strong>Integrity check failed:</strong> {{ reason }}. The audit trail may have been tampered with.</p>{% endif %}
<table>
  <thead><tr><th>#</th><th>Time</th><th>Action</th><th>Actor</th><th>Subject</th><th>IP</th></tr></thead>
  <tbody>
  {% each entries as e %}<tr><td>{{ e.seq }}</td><td>{{ e.at }}</td><td>{{ e.action }}</td><td>{% if e.actor_name %}<span title="{{ e.actor | attr }}">{{ e.actor_name }}</span>{% else %}<code>{{ e.actor }}</code>{% endif %}</td><td>{% if e.subject_name %}<span title="{{ e.subject | attr }}">{{ e.subject_name }}</span>{% else %}<code>{{ e.subject }}</code>{% endif %}</td><td>{{ e.ip }}</td></tr>{% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
