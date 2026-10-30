{% include "partials/head" %}
<h1>Forgot your password?</h1>
{% if sent %}
<p class="ok" role="status">If an account with that email exists, we've sent a link to reset the password. It is valid for 30 minutes.</p>
{% else %}
{% if available %}
<form method="post" action="/admin/forgot" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Email of your account <input name="email" type="email" required autocomplete="email"></label>
  <button>Send reset link</button>
</form>
{% else %}
<p>Email is not configured on this site. Ask the site owner to run <code>bin/bastion reset-link &lt;username&gt;</code> on the server.</p>
{% endif %}
{% endif %}
<p><a href="/admin/login">Back to sign in</a></p>
{% include "partials/foot" %}
