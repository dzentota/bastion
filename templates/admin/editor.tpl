{% include "partials/head" %}
<p><a href="/admin">← {{ t.all_content }}</a></p>
<h1>{% if entry %}{% if is_page %}{{ t.edit_page }}{% else %}{{ t.edit_post }}{% endif %}{% else %}{% if is_page %}{{ t.new_page }}{% else %}{{ t.new_post }}{% endif %}{% endif %}</h1>
{% include "partials/errors" %}
<form method="post" action="{{ action | url }}" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  {% if not entry %}<input type="hidden" name="type" value="{{ values.type | attr }}">{% endif %}
  {% if languages %}<label>{{ t.language }} <select name="lang">{% each languages as l %}<option value="{{ l.code | attr }}"{% if l.selected %} selected{% endif %}>{{ l.code }}</option>{% endeach %}</select></label>{% endif %}
  {% if entry %}<p class="hint">{{ t.language_label }} <code>{{ entry.lang }}</code></p>{% endif %}
  <label>{{ t.title }} <input name="title" value="{{ values.title | attr }}" required maxlength="200"></label>
  <label>{{ t.slug_address }} <input name="slug" value="{{ values.slug | attr }}" required pattern="[a-z0-9]+(-[a-z0-9]+)*" maxlength="96"></label>
  {% if not is_page %}
  <label>{{ t.categories }} <input name="categories" value="{{ values.categories | attr }}" maxlength="600" placeholder="{{ t.categories_placeholder | attr }}"></label>
  <label>{{ t.tags }} <input name="tags" value="{{ values.tags | attr }}" maxlength="1600" placeholder="{{ t.tags_placeholder | attr }}"></label>
  <p class="hint">{{ t.terms_hint }}</p>
  {% else %}
  <p class="hint">{{ t.pages_hint }}</p>
  <label class="inline"><input type="checkbox" name="in_menu" value="1"{% if values.in_menu %} checked{% endif %}> {{ t.show_in_menu }}</label>
  <label>{{ t.menu_position }} <input name="menu_position" value="{{ values.menu_position | attr }}" inputmode="numeric" pattern="[1-9][0-9]?" maxlength="2"></label>
  {% endif %}
  <fieldset>
    <legend>{{ t.content_blocks }}</legend>
    {% each rows as row %}
    <div class="block">
      <select name="blocks[{{ row.i | attr }}][type]" aria-label="{{ t.block_type | attr }}">
        <option value="paragraph"{% if row.is_paragraph %} selected{% endif %}>{{ t.block_paragraph }}</option>
        <option value="heading"{% if row.is_heading %} selected{% endif %}>{{ t.block_heading }}</option>
        <option value="quote"{% if row.is_quote %} selected{% endif %}>{{ t.block_quote }}</option>
        <option value="image"{% if row.is_image %} selected{% endif %}>{{ t.block_image }}</option>
      </select>
      <div>
        <textarea name="blocks[{{ row.i | attr }}][text]" rows="3" aria-label="{{ t.block_text | attr }}">{{ row.text }}</textarea>
        <select name="blocks[{{ row.i | attr }}][media]" aria-label="{{ t.block_media | attr }}">
          <option value="">{{ t.block_media_none }}</option>
          {% each row.media as m %}<option value="{{ m.id | attr }}"{% if m.selected %} selected{% endif %}>{{ m.name }}</option>{% endeach %}
        </select>
      </div>
    </div>
    {% endeach %}
    <p class="hint">{{ t.blocks_hint }} <a href="/admin/media">{{ t.blocks_hint_media_link }}</a>{{ t.blocks_hint_suffix }}</p>
  </fieldset>
  <button>{% if entry.published %}{{ t.save }}{% else %}{{ t.save_draft }}{% endif %}</button>
</form>
{% if entry %}{% if can_publish %}{% if not entry.published %}
<form method="post" action="/admin/entries/{{ entry.id | attr }}/publish" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <button>{{ t.publish }}</button>
</form>
{% endif %}{% endif %}{% endif %}
{% if translations %}
<section class="card" aria-labelledby="translations">
  <h2 id="translations">{{ t.translations }}</h2>
  <table>
    <tbody>
    {% each translations as tr %}<tr>
      <td><code>{{ tr.lang }}</code></td>
      <td>{% if tr.current %}{{ tr.title }} {{ t.this_entry }}{% else %}{% if tr.edit %}<a href="{{ tr.edit | url }}">{{ tr.title }}</a>{% endif %}{% endif %}</td>
      <td>{% if tr.edit %}{% if tr.published %}{{ t.translation_published }}{% else %}{{ t.translation_draft }}{% endif %}{% endif %}</td>
      <td>{% if not tr.edit %}<form method="post" action="/admin/entries/{{ entry.id | attr }}/translations">
        <input type="hidden" name="_token" value="{{ csrf | attr }}">
        <input type="hidden" name="lang" value="{{ tr.lang | attr }}">
        <button>{{ t.add_translation }}</button>
      </form>{% endif %}</td>
    </tr>{% endeach %}
    </tbody>
  </table>
</section>
{% endif %}
{% include "partials/foot" %}
