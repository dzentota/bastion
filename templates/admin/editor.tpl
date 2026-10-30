{% include "partials/head" %}
<p><a href="/admin">← All posts</a></p>
<h1>{% if entry %}Edit post{% else %}New post{% endif %}</h1>
{% include "partials/errors" %}
<form method="post" action="{{ action | url }}" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <label>Title <input name="title" value="{{ values.title | attr }}" required maxlength="200"></label>
  <label>Slug (address) <input name="slug" value="{{ values.slug | attr }}" required pattern="[a-z0-9]+(-[a-z0-9]+)*" maxlength="96"></label>
  <fieldset>
    <legend>Content blocks</legend>
    {% each rows as row %}
    <div class="block">
      <select name="blocks[{{ row.i | attr }}][type]" aria-label="Block type">
        <option value="paragraph"{% if row.is_paragraph %} selected{% endif %}>Paragraph</option>
        <option value="heading"{% if row.is_heading %} selected{% endif %}>Heading</option>
        <option value="quote"{% if row.is_quote %} selected{% endif %}>Quote</option>
      </select>
      <textarea name="blocks[{{ row.i | attr }}][text]" rows="3" aria-label="Block text">{{ row.text }}</textarea>
    </div>
    {% endeach %}
    <p class="hint">Empty blocks are ignored. Text is shown exactly as typed — HTML is not interpreted.</p>
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
