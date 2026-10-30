{% include "partials/head" %}
<h1>Choose a new password</h1>
{% if invalid %}
<p class="errors" role="alert">This reset link is invalid or has expired. <a href="/admin/forgot">Request a new one</a>.</p>
{% else %}
{% include "partials/errors" %}
<form method="post" action="/admin/reset" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <p>Account: <strong>{{ username }}</strong></p>
  <label>New password (12+ characters, hard to guess) <input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
  <p class="hint">Your two-factor authentication stays enabled. All other sessions will be signed out.</p>
  <button>Save password</button>
</form>
{% endif %}
{% include "partials/foot" %}
