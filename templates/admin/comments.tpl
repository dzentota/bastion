{% include "partials/head" %}
<h1>{{ t.comments_awaiting }}</h1>
{% each items as c %}
<div class="card">
  <p><strong>{{ c.author }}</strong> · {{ c.date }}{% if c.links %} · <span class="warning-inline">{{ t.contains_links }}</span>{% endif %}</p>
  {% if c.entry %}<p class="hint">{{ t.comment_on }} <a href="{{ c.entry.url | url }}">{{ c.entry.title }}</a></p>{% endif %}
  <p>{% each c.lines as line %}{{ line }}<br>{% endeach %}</p>
  <div class="actions">
    <form method="post" action="/admin/comments/{{ c.id | attr }}/approve"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button>{{ t.approve }}</button></form>
    <form method="post" action="/admin/comments/{{ c.id | attr }}/reject"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="secondary">{{ t.reject }}</button></form>
    <form method="post" action="/admin/comments/{{ c.id | attr }}/spam"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="secondary">{{ t.spam }}</button></form>
  </div>
</div>
{% endeach %}
{% if not items %}<p>{{ t.nothing_to_moderate }}</p>{% endif %}
{% include "partials/foot" %}
