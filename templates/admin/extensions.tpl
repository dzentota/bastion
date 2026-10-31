{% include "partials/head" %}
<h1>{{ t.extensions }}</h1>
{% include "partials/errors" %}
{% if notice %}<p class="ok" role="status">{{ notice }}</p>{% endif %}
<form method="post" action="/admin/extensions" enctype="multipart/form-data" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.package_zip }} <input type="file" name="package" accept=".zip,application/zip" required></label>
  <label>{{ t.signature_sig }} <input type="file" name="signature" accept=".sig" required></label>
  <p class="hint">{{ t.extensions_hint }}</p>
  <button>{{ t.install }}</button>
</form>
{% each items as e %}
<div class="card">
  <p><strong>{{ e.name }}</strong> {{ e.version }} · {% if e.enabled %}<span class="ok">{{ t.ext_enabled }}</span>{% else %}{{ t.ext_disabled }}{% endif %}</p>
  <p class="hint">{{ t.publisher_fingerprint }}<br><code class="wrap-any">{{ e.fingerprint }}</code></p>
  <p>{{ t.permissions_requested }}</p>
  <ul>{% each e.caps as c %}<li><code>{{ c.id }}</code> — {{ c.text }}</li>{% endeach %}{% if not e.caps %}<li>{{ t.permissions_none }}</li>{% endif %}</ul>
  {% if e.enabled %}
  <form method="post" action="/admin/extensions/disable"><input type="hidden" name="_token" value="{{ csrf | attr }}"><input type="hidden" name="name" value="{{ e.path | attr }}"><button class="secondary">{{ t.disable }}</button></form>
  {% else %}
  <form method="post" action="/admin/extensions/enable"><input type="hidden" name="_token" value="{{ csrf | attr }}"><input type="hidden" name="name" value="{{ e.path | attr }}"><button>{{ t.enable_and_grant }}</button></form>
  {% endif %}
</div>
{% endeach %}
{% include "partials/foot" %}
