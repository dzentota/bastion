{% include "partials/head" %}
<p><a href="/admin">← Posts</a></p>
<h1>Audit trail</h1>
{% if intact %}<p class="ok" role="status">Integrity verified: {{ count }} entries, chain and anchor intact.</p>{% else %}<p class="errors" role="alert"><strong>Integrity check failed:</strong> {{ reason }}. The audit trail may have been tampered with.</p>{% endif %}
<table>
  <thead><tr><th>#</th><th>Time</th><th>Action</th><th>Actor</th><th>Subject</th><th>IP</th></tr></thead>
  <tbody>
  {% each entries as e %}<tr><td>{{ e.seq }}</td><td>{{ e.at }}</td><td>{{ e.action }}</td><td><code>{{ e.actor }}</code></td><td><code>{{ e.subject }}</code></td><td>{{ e.ip }}</td></tr>{% endeach %}
  </tbody>
</table>
{% include "partials/foot" %}
