{% include "partials/head" %}
<p><a href="/admin">← All posts</a></p>
<h1>{% if entry %}Edit post{% else %}New post{% endif %}</h1>
{% include "partials/errors" %}
<form method="post" action="{{ action | url }}" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Title <input name="title" value="{{ values.title | attr }}" required maxlength="200"></label>
  <label>Slug (address) <input name="slug" value="{{ values.slug | attr }}" required pattern="[a-z0-9]+(-[a-z0-9]+)*" maxlength="96"></label>
  <label>Categories <input name="categories" value="{{ values.categories | attr }}" maxlength="600" placeholder="news, security"></label>
  <label>Tags <input name="tags" value="{{ values.tags | attr }}" maxlength="1600" placeholder="php, release"></label>
  <p class="hint">Comma-separated slugs (lowercase letters, digits, dashes). Up to 5 categories and 15 tags.</p>
  <fieldset>
    <legend>Content blocks</legend>
    {% each rows as row %}
    <div class="block">
      <select name="blocks[{{ row.i | attr }}][type]" aria-label="Block type">
        <option value="paragraph"{% if row.is_paragraph %} selected{% endif %}>Paragraph</option>
        <option value="heading"{% if row.is_heading %} selected{% endif %}>Heading</option>
        <option value="quote"{% if row.is_quote %} selected{% endif %}>Quote</option>
        <option value="image"{% if row.is_image %} selected{% endif %}>Image</option>
      </select>
      <div>
        <textarea name="blocks[{{ row.i | attr }}][text]" rows="3" aria-label="Block text (alt text for images)">{{ row.text }}</textarea>
        <select name="blocks[{{ row.i | attr }}][media]" aria-label="Image from the media library">
          <option value="">— image (for Image blocks) —</option>
          {% each row.media as m %}<option value="{{ m.id | attr }}"{% if m.selected %} selected{% endif %}>{{ m.name }}</option>{% endeach %}
        </select>
      </div>
    </div>
    {% endeach %}
    <p class="hint">Empty blocks are ignored. Text is shown exactly as typed — HTML is not interpreted. For an Image block pick a file from the <a href="/admin/media">media library</a>; the text becomes its alt text.</p>
  </fieldset>
  <button>Save draft</button>
</form>
{% if entry %}{% if can_publish %}{% if not entry.published %}
<form method="post" action="/admin/entries/{{ entry.id | attr }}/publish" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <button>Publish</button>
</form>
{% endif %}{% endif %}{% endif %}
{% include "partials/foot" %}
