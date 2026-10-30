{% include "partials/head" %}
<h1>Two-factor code</h1>
{% include "partials/errors" %}
<form method="post" action="/admin/2fa" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>6-digit code from your authenticator app
    <input name="code" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" autofocus></label>
  <button>Verify</button>
</form>
{% include "partials/foot" %}
