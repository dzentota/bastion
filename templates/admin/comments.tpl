{% include "partials/head" %}
<p><a href="/admin">← Posts</a></p>
<h1>Comments awaiting moderation</h1>
{% each items as c %}
<div class="card">
  <p><strong>{{ c.author }}</strong> · {{ c.date }}{% if c.links %} · <span class="warning-inline">contains links</span>{% endif %}</p>
  <p>{% each c.lines as line %}{{ line }}<br>{% endeach %}</p>
  <div class="actions">
    <form method="post" action="/admin/comments/{{ c.id | attr }}/approve"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button>Approve</button></form>
    <form method="post" action="/admin/comments/{{ c.id | attr }}/reject"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="secondary">Reject</button></form>
    <form method="post" action="/admin/comments/{{ c.id | attr }}/spam"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="secondary">Spam</button></form>
  </div>
</div>
{% endeach %}
{% if not items %}<p>Nothing to moderate.</p>{% endif %}
{% include "partials/foot" %}
