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
    <legend>Administrator</legend>
    <label>Username <input name="username" value="{{ username | attr }}" required autocomplete="username"></label>
    <label>Password (12+ characters, hard to guess) <input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
  </fieldset>
  <button>Install</button>
</form>
{% include "partials/foot" %}
