{% include "partials/head" %}
<h1>{{ t.choose_new_password }}</h1>
{% if invalid %}
<p class="errors" role="alert">{{ t.reset_link_invalid }} <a href="/admin/forgot">{{ t.request_new_link }}</a>.</p>
{% else %}
{% include "partials/errors" %}
<form method="post" action="/admin/reset" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <p>{{ t.account_label }} <strong>{{ username }}</strong></p>
  <label>{{ t.new_password }} <input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
  <p class="hint">{{ t.reset_hint }}</p>
  <button>{{ t.save_password }}</button>
</form>
{% endif %}
{% include "partials/foot" %}
