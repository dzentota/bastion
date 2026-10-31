{% include "partials/head" %}
<h1>{{ t.totp_setup_title }}</h1>
<p>{{ t.totp_setup_intro }}</p>
{% include "partials/errors" %}
<div class="card">
  <p>{{ t.setup_key }}</p>
  <p class="secret"><code>{{ secret }}</code></p>
  <details><summary>{{ t.otpauth_link }}</summary><p><code class="wrap-any">{{ uri }}</code></p></details>
</div>
<form method="post" action="/admin/2fa/setup" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.six_digit_code }} <input name="code" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></label>
  <button>{{ t.confirm }}</button>
</form>
{% include "partials/foot" %}
