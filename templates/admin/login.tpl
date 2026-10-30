{% include "partials/head" %}
<h1>Sign in</h1>
{% include "partials/errors" %}
<form method="post" action="/admin/login" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Username <input name="username" required autocomplete="username" autofocus></label>
  <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
  <button>Continue</button>
</form>
{% include "partials/foot" %}
