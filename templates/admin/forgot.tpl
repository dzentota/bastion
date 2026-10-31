{% include "partials/head" %}
<h1>{{ t.forgot_password }}</h1>
{% if sent %}
<p class="ok" role="status">{{ t.reset_link_sent }}</p>
{% else %}
{% if available %}
<form method="post" action="/admin/forgot" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.account_email }} <input name="email" type="email" required autocomplete="email"></label>
  <button>{{ t.send_reset_link }}</button>
</form>
{% else %}
<p>{{ t.mail_not_configured }} <code>bin/bastion reset-link &lt;username&gt;</code> {{ t.mail_not_configured_suffix }}</p>
{% endif %}
{% endif %}
<p><a href="/admin/login">{{ t.back_to_sign_in }}</a></p>
{% include "partials/foot" %}
