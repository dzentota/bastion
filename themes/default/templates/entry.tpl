{% include "partials/head" %}
{% if tree.section %}<nav class="section" aria-label="{{ t.section_nav | attr }}">
  <a href="{{ tree.section.root.url | url }}"{% if tree.section.root.current %} aria-current="page"{% endif %}>{{ tree.section.root.title }}</a>
  <ul>{% each tree.section.items as s %}<li class="depth-{{ s.depth | attr }}"><a href="{{ s.url | url }}"{% if s.current %} aria-current="page"{% endif %}>{{ s.title }}</a></li>{% endeach %}</ul>
</nav>{% endif %}
<article>
  {% if tree.breadcrumbs %}<nav class="breadcrumbs" aria-label="{{ t.breadcrumbs | attr }}">{% each tree.breadcrumbs as b %}<a href="{{ b.url | url }}">{{ b.title }}</a> › {% endeach %}</nav>{% endif %}
  <h1>{{ entry.title }}</h1>
  {% if comments_open %}<time>{{ entry.date }}</time>{% endif %}
  {{ entry.body }}
  {% if tree.children %}<nav class="children" aria-label="{{ t.child_pages | attr }}"><h2>{{ t.child_pages }}</h2><ul>{% each tree.children as c %}<li><a href="{{ c.url | url }}">{{ c.title }}</a></li>{% endeach %}</ul></nav>{% endif %}
  {% if entry.categories %}<p class="terms">{{ t.categories_label }} {% each entry.categories as term %}<a href="{{ term.url | url }}">{{ term.name }}</a> {% endeach %}</p>{% endif %}
  {% if entry.tags %}<p class="terms">{{ t.tags_label }} {% each entry.tags as term %}<a href="{{ term.url | url }}">#{{ term.name }}</a> {% endeach %}</p>{% endif %}
</article>
{% if comments_open %}
<section class="comments" id="comments">
  <h2>{{ t.comments }}</h2>
  {% each comments as c %}
  <div class="comment">
    <p class="comment-meta"><strong>{{ c.author }}</strong> · <time>{{ c.date }}</time></p>
    <p>{% each c.lines as line %}{{ line }}<br>{% endeach %}</p>
  </div>
  {% endeach %}
  {% if not comments %}<p>{{ t.no_comments }}</p>{% endif %}

  {% if comment_form.sent %}
  <p class="notice" role="status">{{ t.comment_sent }}</p>
  {% else %}
  <form method="post" action="/comments" class="comment-form">
    <input type="hidden" name="entry" value="{{ comment_form.entry | attr }}">
    <input type="hidden" name="_timestamp" value="{{ comment_form.timestamp | attr }}">
    <div class="hp" aria-hidden="true"><label>{{ t.honeypot }} <input name="website" tabindex="-1" autocomplete="off"></label></div>
    {% if comment_form.error %}<p class="error" role="alert">{{ comment_form.error }}</p>{% endif %}
    <label>{{ t.name }} <input name="author" value="{{ comment_form.author | attr }}" required maxlength="60" autocomplete="nickname"></label>
    <label>{{ t.comment }} <textarea name="body" required maxlength="5000" rows="5">{{ comment_form.body }}</textarea></label>
    <p class="hint">{{ t.comment_hint }}</p>
    <button>{{ t.post_comment }}</button>
  </form>
  {% endif %}
</section>
{% endif %}
{% include "partials/foot" %}
