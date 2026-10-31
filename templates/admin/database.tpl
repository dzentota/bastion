{% include "partials/head" %}
<h1>Database</h1>
{% if error %}<p class="errors" role="alert">{{ error }}</p>{% endif %}
{% if current %}<p class="ok" role="status">The database schema is up to date.</p><p><a href="/admin">← Content</a></p>{% endif %}
{% if tampered %}
<div class="errors" role="alert">
  <p><strong>Applied migrations do not match this release.</strong> Updating is blocked. Restore the release files, or restore the database from a backup in <code>var/backups</code>.</p>
  <ul>{% each tampered as id %}<li><code>{{ id }}</code></li>{% endeach %}</ul>
</div>
{% endif %}
{% if pending %}
<p>This release needs database updates. The public site is in maintenance mode until they are applied.</p>
<ul>{% each pending as id %}<li><code>{{ id }}</code></li>{% endeach %}</ul>
<p>A full backup is written to <code>var/backups</code> first. Rollback means restoring that backup.</p>
<form method="post" action="/admin/database">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Authenticator code <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
  <button>Update database</button>
</form>
{% endif %}
{% include "partials/foot" %}
