{% include "partials/head" %}
<h1>{% if entry %}{% if is_page %}{{ t.edit_page }}{% else %}{{ t.edit_post }}{% endif %}{% else %}{% if is_page %}{{ t.new_page }}{% else %}{{ t.new_post }}{% endif %}{% endif %}</h1>
{% include "partials/errors" %}
{% if managed %}<p class="notice" role="status">{{ t.managed_by_repo }} <code>{{ managed }}</code>. {{ t.managed_hint }}</p>{% endif %}
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
  <label>{{ t.parent_page }} <select name="parent"><option value="">{{ t.parent_none }}</option>{% each parents as p %}<option value="{{ p.id | attr }}"{% if p.selected %} selected{% endif %}>{{ p.label }}</option>{% endeach %}</select></label>
  <label>{{ t.page_order }} <input name="page_position" value="{{ values.page_position | attr }}" inputmode="numeric" pattern="[0-9]{1,3}" maxlength="3"></label>
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
        <option value="code"{% if row.is_code %} selected{% endif %}>{{ t.block_code }}</option>
        <option value="table"{% if row.is_table %} selected{% endif %}>{{ t.block_table }}</option>
        <option value="callout"{% if row.is_callout %} selected{% endif %}>{{ t.block_callout }}</option>
        <option value="threatmodel"{% if row.is_threatmodel %} selected{% endif %}>{{ t.block_threatmodel }}</option>
      </select>
      <div>
        <textarea name="blocks[{{ row.i | attr }}][text]" rows="3" aria-label="{{ t.block_text | attr }}">{{ row.text }}</textarea>
        <select name="blocks[{{ row.i | attr }}][media]" aria-label="{{ t.block_media | attr }}">
          <option value="">{{ t.block_media_none }}</option>
          {% each row.media as m %}<option value="{{ m.id | attr }}"{% if m.selected %} selected{% endif %}>{{ m.name }}</option>{% endeach %}
        </select>
        <select name="blocks[{{ row.i | attr }}][option]" aria-label="{{ t.block_option | attr }}">
          <option value="">{{ t.block_option_none }}</option>
          <optgroup label="{{ t.block_option_language | attr }}">{% each row.languages as o %}<option value="{{ o.value | attr }}"{% if o.selected %} selected{% endif %}>{{ o.value }}</option>{% endeach %}</optgroup>
          <optgroup label="{{ t.block_option_callout | attr }}">{% each row.variants as o %}<option value="{{ o.value | attr }}"{% if o.selected %} selected{% endif %}>{{ o.value }}</option>{% endeach %}</optgroup>
          <optgroup label="{{ t.block_option_threatmodel | attr }}">{% each row.tm_views as o %}<option value="{{ o.value | attr }}"{% if o.selected %} selected{% endif %}>{{ o.value }}</option>{% endeach %}</optgroup>
          <optgroup label="{{ t.block_option_table | attr }}"><option value="header"{% if row.header %} selected{% endif %}>{{ t.block_option_header }}</option></optgroup>
        </select>
      </div>
    </div>
    {% endeach %}
    <p class="hint">{{ t.blocks_hint_new }}</p>
    <p class="hint">{{ t.blocks_hint_tm }}</p>
    <p class="hint">{{ t.blocks_hint }} <a href="/admin/media">{{ t.blocks_hint_media_link }}</a>{{ t.blocks_hint_suffix }}</p>
  </fieldset>
  <button>{% if entry.published %}{{ t.save_changes }}{% else %}{{ t.save_draft }}{% endif %}</button>
  {% if entry.published %}<p class="hint">{{ t.save_published_hint }}</p>{% endif %}
</form>
{% if entry %}
{% if entry.pending %}<p class="notice" role="status">{{ t.pending_changes }}</p>{% endif %}
{% if slug_conflict %}<p class="errors" role="alert">{{ t.publish_slug_conflict }}</p>{% endif %}
{% if can_publish %}{% if entry.pending %}
<form method="post" action="/admin/entries/{{ entry.id | attr }}/publish" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <button>{{ t.publish_changes }}</button>
</form>
{% endif %}{% if not entry.published %}
<form method="post" action="/admin/entries/{{ entry.id | attr }}/publish" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <button>{{ t.publish }}</button>
</form>
{% endif %}{% endif %}
<form method="post" action="/admin/entries/{{ entry.id | attr }}/preview" class="inline"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="link">{{ t.preview }}</button></form>
<p><a href="/admin/entries/{{ entry.id | attr }}/revisions">{{ t.revision_history }}</a></p>
{% endif %}
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
