{% include "partials/head" %}
<p><a href="/admin">← Posts</a></p>
<h1>Media library</h1>
{% if degraded %}<p class="warning" role="status"><strong>Reduced security mode:</strong> files are stored on this server. Connect S3-compatible storage (Cloudflare R2, Backblaze B2, AWS S3) to keep uploads away from your site's code.</p>{% endif %}
{% include "partials/errors" %}
<form method="post" action="/admin/media" enctype="multipart/form-data" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>File (JPEG, PNG, WebP, GIF or PDF, up to 10 MB) <input type="file" name="file" required accept="image/jpeg,image/png,image/webp,image/gif,application/pdf"></label>
  <p class="hint">Images are re-encoded: location data and other metadata are removed. Animated GIFs become still images.</p>
  <button>Upload</button>
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
