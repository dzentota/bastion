{% include "partials/head" %}
<h1>Install Bastion</h1>
<p>To prove you own this site, open the file <code>var/install.token</code> via FTP or your hosting file manager and paste its contents below.</p>
{% include "partials/errors" %}
<form method="post" action="/install" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Install token <input name="install_token" required autocomplete="off" spellcheck="false"></label>
  <fieldset>
    <legend>Database</legend>
    <label><input type="radio" name="driver" value="sqlite"{% if not driver_mysql %} checked{% endif %}> SQLite (simplest)</label>
    <label><input type="radio" name="driver" value="mysql"{% if driver_mysql %} checked{% endif %}> MySQL / MariaDB</label>
    <label>Host <input name="db_host" value="localhost"></label>
    <label>Port <input name="db_port" value="3306" inputmode="numeric"></label>
    <label>Database <input name="db_name"></label>
    <label>User <input name="db_user"></label>
    <label>Password <input name="db_password" type="password" autocomplete="off"></label>
  </fieldset>
  <fieldset>
    <legend>Media storage (recommended)</legend>
    <p class="hint">Uploads are safest in S3-compatible object storage (Cloudflare R2, Backblaze B2, AWS S3): files never sit next to your site's code. Leave empty to store files on this server in reduced security mode — you can connect storage later.</p>
    <label>Endpoint (https://…) <input name="s3_endpoint" value="{{ s3.endpoint | attr }}" placeholder="https://ACCOUNT.r2.cloudflarestorage.com"></label>
    <label>Bucket <input name="s3_bucket" value="{{ s3.bucket | attr }}"></label>
    <label>Region <input name="s3_region" value="{{ s3.region | attr }}" placeholder="auto"></label>
    <label>Access key <input name="s3_access_key" value="{{ s3.access_key | attr }}" autocomplete="off"></label>
    <label>Secret key <input name="s3_secret_key" type="password" autocomplete="off"></label>
  </fieldset>
  <fieldset>
    <legend>Outgoing mail (for password resets)</legend>
    <p class="hint">Your hosting or email provider gives these settings. Only encrypted connections are used: port 465 (TLS) or 587 (STARTTLS). Leave empty to skip — passwords can then be reset from the server with <code>bin/bastion reset-link</code>.</p>
    <label>SMTP server <input name="smtp_host" placeholder="smtp.example.com"></label>
    <label>Port <input name="smtp_port" value="587" inputmode="numeric"></label>
    <label>Username <input name="smtp_user" autocomplete="off"></label>
    <label>Password <input name="smtp_password" type="password" autocomplete="off"></label>
    <label>Send from <input name="smtp_from" type="email" placeholder="noreply@example.com"></label>
  </fieldset>
  <fieldset>
    <legend>Site</legend>
    <label>Languages <input name="languages" value="en" pattern="[a-z]{2}(\s*,\s*[a-z]{2})*" maxlength="64" spellcheck="false"></label>
    <p class="hint">Two-letter codes separated by commas. The first one is the default language, for example <code>en, ru</code>.</p>
  </fieldset>
  <fieldset>
    <legend>Administrator</legend>
    <label>Username <input name="username" value="{{ username | attr }}" required autocomplete="username"></label>
    <label>Email (for password resets) <input name="email" type="email" value="{{ email | attr }}" required autocomplete="email"></label>
    <label>Password (12+ characters, hard to guess) <input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
  </fieldset>
  <button>Install</button>
</form>
{% include "partials/foot" %}
