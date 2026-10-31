{% include "partials/head" %}
<p><a href="/admin/entries/{{ entry.id | attr }}/revisions">← {{ t.revision_history }}</a></p>
<h1>{{ entry.title }}: #{{ old }} → #{{ new }}</h1>
{% if too_large %}<p class="notice" role="status">{{ t.diff_too_large }}</p>{% endif %}
{% if not changed %}<p>{{ t.diff_no_changes }}</p>{% endif %}
<pre class="diff">{% each lines as l %}{% if l.add %}<ins>+ {{ l.text }}</ins>{% else %}{% if l.del %}<del>− {{ l.text }}</del>{% else %}<span>  {{ l.text }}</span>{% endif %}{% endif %}
{% endeach %}</pre>
{% include "partials/foot" %}
