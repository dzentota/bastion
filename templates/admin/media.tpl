{% include "partials/head" %}
<p><a href="/admin">← {{ t.content }}</a></p>
<h1>{{ t.media_library }}</h1>
{% if degraded %}<p class="warning" role="status"><strong>{{ t.reduced_security_mode }}</strong> {{ t.media_degraded_hint }}</p>{% endif %}
{% include "partials/errors" %}
<form method="post" action="/admin/media" enctype="multipart/form-data" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>{{ t.media_file }} <input type="file" name="file" required accept="image/jpeg,image/png,image/webp,image/gif,application/pdf"></label>
  <p class="hint">{{ t.media_reencode_hint }}</p>
  <button>{{ t.upload }}</button>
</form>
<div class="media-grid">
{% each items as m %}
  <figure>
    {% if m.is_image %}<img src="{{ m.url | url }}" alt="" loading="lazy">{% else %}<a href="{{ m.url | url }}">PDF</a>{% endif %}
    <figcaption>{{ m.name }} · {{ m.size }}</figcaption>
  </figure>
{% endeach %}
</div>
{% include "partials/foot" %}
