{% include "partials/head" %}
<h1>{{ t.sign_in }}</h1>
{% include "partials/errors" %}
<form method="post" action="/admin/login" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.username }} <input name="username" required autocomplete="username" autofocus></label>
  <label>{{ t.password }} <input name="password" type="password" required autocomplete="current-password"></label>
  <button>{{ t.continue }}</button>
</form>
<p><a href="/admin/forgot">{{ t.forgot_password }}</a></p>
{% include "partials/foot" %}
