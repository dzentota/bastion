{% include "partials/head" %}
<p><a href="/admin">← Content</a></p>
<h1>Extensions</h1>
{% include "partials/errors" %}
{% if notice %}<p class="ok" role="status">{{ notice }}</p>{% endif %}
<form method="post" action="/admin/extensions" enctype="multipart/form-data" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Package (.zip) <input type="file" name="package" accept=".zip,application/zip" required></label>
  <label>Signature (.sig) <input type="file" name="signature" accept=".sig" required></label>
  <p class="hint">Only signed packages are accepted. The code is checked before installation; nothing runs until you enable the extension. An installed extension can only be updated by the same publisher.</p>
  <button>Install</button>
</form>
{% each items as e %}
<div class="card">
  <p><strong>{{ e.name }}</strong> {{ e.version }} · {% if e.enabled %}<span class="ok">enabled</span>{% else %}disabled{% endif %}</p>
  <p class="hint">Publisher key fingerprint:<br><code class="wrap-any">{{ e.fingerprint }}</code></p>
  <p>Permissions it asks for:</p>
  <ul>{% each e.caps as c %}<li><code>{{ c.id }}</code> — {{ c.text }}</li>{% endeach %}{% if not e.caps %}<li>none</li>{% endif %}</ul>
  {% if e.enabled %}
  <form method="post" action="/admin/extensions/disable"><input type="hidden" name="_token" value="{{ csrf | attr }}"><input type="hidden" name="name" value="{{ e.path | attr }}"><button class="secondary">Disable</button></form>
  {% else %}
  <form method="post" action="/admin/extensions/enable"><input type="hidden" name="_token" value="{{ csrf | attr }}"><input type="hidden" name="name" value="{{ e.path | attr }}"><button>Enable and grant these permissions</button></form>
  {% endif %}
</div>
{% endeach %}
{% include "partials/foot" %}
