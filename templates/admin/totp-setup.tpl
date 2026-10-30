{% include "partials/head" %}
<h1>Set up two-factor authentication</h1>
<p>Administrators and editors must use a second factor. Add this key to an authenticator app (1Password, Bitwarden, Google Authenticator, Aegis…), then enter the code it shows.</p>
{% include "partials/errors" %}
<div class="card">
  <p>Setup key:</p>
  <p class="secret"><code>{{ secret }}</code></p>
  <details><summary>otpauth link</summary><p><code class="wrap-any">{{ uri }}</code></p></details>
</div>
<form method="post" action="/admin/2fa/setup" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>6-digit code <input name="code" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></label>
  <button>Confirm</button>
</form>
{% include "partials/foot" %}
