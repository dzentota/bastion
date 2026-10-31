{% include "partials/head" %}
<p><a href="/admin">← {{ t.content }}</a></p>
<h1>{{ t.site_menu }}</h1>
{% if languages %}<p>{% each languages as l %}{% if l.current %}<strong>{{ l.code }}</strong>{% else %}<a href="/admin/menu?lang={{ l.code | attr }}">{{ l.code }}</a>{% endif %} {% endeach %}</p>{% endif %}
<form method="post" action="/admin/menu" class="card">
  <input type="hidden" name="_token" value="{{ csrf | attr }}">
  <input type="hidden" name="lang" value="{{ lang | attr }}">
  {% if items %}
  <table>
    <thead><tr><th>{{ t.title }}</th><th>{{ t.menu_position }}</th><th>{{ t.menu_remove }}</th></tr></thead>
    <tbody>
    {% each items as i %}<tr>
      <td><a href="/admin/entries/{{ i.id | attr }}/edit">{{ i.title }}</a>{% if not i.published %} <span class="hint">({{ t.menu_hidden_draft }})</span>{% endif %}</td>
      <td><input name="position[{{ i.id | attr }}]" value="{{ i.position | attr }}" inputmode="numeric" pattern="[1-9][0-9]?" maxlength="2" aria-label="{{ t.menu_position | attr }}"></td>
      <td><input type="checkbox" name="remove[]" value="{{ i.id | attr }}" aria-label="{{ t.menu_remove | attr }}"></td>
    </tr>{% endeach %}
    </tbody>
  </table>
  {% else %}<p>{{ t.menu_empty }}</p>{% endif %}
  {% if not full %}{% if candidates %}
  <label>{{ t.menu_add }} <select name="add"><option value="">—</option>{% each candidates as c %}<option value="{{ c.id | attr }}">{{ c.title }}</option>{% endeach %}</select></label>
  <label>{{ t.menu_position }} <input name="add_position" value="10" inputmode="numeric" pattern="[1-9][0-9]?" maxlength="2"></label>
  {% endif %}{% else %}<p class="hint">{{ t.menu_full }}</p>{% endif %}
  <button>{{ t.save_changes }}</button>
</form>
{% include "partials/foot" %}
