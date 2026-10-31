{% include "partials/head" %}
<h1>{{ t.database }}</h1>
{% if error %}<p class="errors" role="alert">{{ error }}</p>{% endif %}
{% if current %}<p class="ok" role="status">{{ t.schema_up_to_date }}</p><p><a href="/admin">← {{ t.content }}</a></p>{% endif %}
{% if tampered %}
<div class="errors" role="alert">
  <p><strong>{{ t.migrations_mismatch }}</strong> {{ t.migrations_mismatch_hint }} <code>var/backups</code>.</p>
  <ul>{% each tampered as id %}<li><code>{{ id }}</code></li>{% endeach %}</ul>
</div>
{% endif %}
{% if pending %}
<p>{{ t.db_updates_needed }}</p>
<ul>{% each pending as id %}<li><code>{{ id }}</code></li>{% endeach %}</ul>
<p>{{ t.backup_written_to }} <code>var/backups</code> {{ t.backup_rollback }}</p>
<form method="post" action="/admin/database">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.authenticator_code }} <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
  <button>{{ t.update_database }}</button>
</form>
{% endif %}
{% include "partials/foot" %}
