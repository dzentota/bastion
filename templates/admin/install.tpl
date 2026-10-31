{% include "partials/head" %}
<h1>{{ t.install_bastion }}</h1>
<p>{{ t.install_intro }} <code>var/install.token</code> {{ t.install_intro_suffix }}</p>
{% include "partials/errors" %}
<form method="post" action="/install" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.install_token }} <input name="install_token" required autocomplete="off" spellcheck="false"></label>
  <fieldset>
    <legend>{{ t.database }}</legend>
    <label><input type="radio" name="driver" value="sqlite"{% if not driver_mysql %} checked{% endif %}> {{ t.driver_sqlite }}</label>
    <label><input type="radio" name="driver" value="mysql"{% if driver_mysql %} checked{% endif %}> {{ t.driver_mysql }}</label>
    <label>{{ t.host }} <input name="db_host" value="localhost"></label>
    <label>{{ t.port }} <input name="db_port" value="3306" inputmode="numeric"></label>
    <label>{{ t.database }} <input name="db_name"></label>
    <label>{{ t.db_user }} <input name="db_user"></label>
    <label>{{ t.password }} <input name="db_password" type="password" autocomplete="off"></label>
  </fieldset>
  <fieldset>
    <legend>{{ t.media_storage }}</legend>
    <p class="hint">{{ t.media_storage_hint }}</p>
    <label>{{ t.s3_endpoint }} <input name="s3_endpoint" value="{{ s3.endpoint | attr }}" placeholder="https://ACCOUNT.r2.cloudflarestorage.com"></label>
    <label>{{ t.s3_bucket }} <input name="s3_bucket" value="{{ s3.bucket | attr }}"></label>
    <label>{{ t.s3_region }} <input name="s3_region" value="{{ s3.region | attr }}" placeholder="auto"></label>
    <label>{{ t.s3_access_key }} <input name="s3_access_key" value="{{ s3.access_key | attr }}" autocomplete="off"></label>
    <label>{{ t.s3_secret_key }} <input name="s3_secret_key" type="password" autocomplete="off"></label>
  </fieldset>
  <fieldset>
    <legend>{{ t.outgoing_mail }}</legend>
    <p class="hint">{{ t.outgoing_mail_hint }} <code>bin/bastion reset-link</code>.</p>
    <label>{{ t.smtp_server }} <input name="smtp_host" placeholder="smtp.example.com"></label>
    <label>{{ t.port }} <input name="smtp_port" value="587" inputmode="numeric"></label>
    <label>{{ t.username }} <input name="smtp_user" autocomplete="off"></label>
    <label>{{ t.password }} <input name="smtp_password" type="password" autocomplete="off"></label>
    <label>{{ t.send_from }} <input name="smtp_from" type="email" placeholder="noreply@example.com"></label>
  </fieldset>
  <fieldset>
    <legend>{{ t.site }}</legend>
    <label>{{ t.languages }} <input name="languages" value="en" pattern="[a-z]{2}(\s*,\s*[a-z]{2})*" maxlength="64" spellcheck="false"></label>
    <p class="hint">{{ t.languages_hint }} <code>en, ru</code>.</p>
  </fieldset>
  <fieldset>
    <legend>{{ t.administrator }}</legend>
    <label>{{ t.username }} <input name="username" value="{{ username | attr }}" required autocomplete="username"></label>
    <label>{{ t.admin_email }} <input name="email" type="email" value="{{ email | attr }}" required autocomplete="email"></label>
    <label>{{ t.admin_password }} <input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
  </fieldset>
  <button>{{ t.install }}</button>
</form>
{% include "partials/foot" %}
