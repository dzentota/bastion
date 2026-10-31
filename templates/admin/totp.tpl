{% include "partials/head" %}
<h1>{{ t.two_factor_code }}</h1>
{% include "partials/errors" %}
<form method="post" action="/admin/2fa" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.code_from_app }}
    <input name="code" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" autofocus></label>
  <button>{{ t.verify }}</button>
</form>
{% include "partials/foot" %}
