{% include "partials/head" %}
<article>
  <h1>{{ entry.title }}</h1>
  <time>{{ entry.date }}</time>
  {{ entry.body }}
</article>
<section class="comments" id="comments">
  <h2>Comments</h2>
  {% each comments as c %}
  <div class="comment">
    <p class="comment-meta"><strong>{{ c.author }}</strong> · <time>{{ c.date }}</time></p>
    <p>{% each c.lines as line %}{{ line }}<br>{% endeach %}</p>
  </div>
  {% endeach %}
  {% if not comments %}<p>No comments yet.</p>{% endif %}

  {% if comment_form.sent %}
  <p class="notice" role="status">Thank you! Your comment will appear after moderation.</p>
  {% else %}
  <form method="post" action="/comments" class="comment-form">
    <input type="hidden" name="entry" value="{{ comment_form.entry | attr }}">
    <input type="hidden" name="_timestamp" value="{{ comment_form.timestamp | attr }}">
    <div class="hp" aria-hidden="true"><label>Leave this empty <input name="website" tabindex="-1" autocomplete="off"></label></div>
    {% if comment_form.error %}<p class="error" role="alert">{{ comment_form.error }}</p>{% endif %}
    <label>Name <input name="author" value="{{ comment_form.author | attr }}" required maxlength="60" autocomplete="nickname"></label>
    <label>Comment <textarea name="body" required maxlength="5000" rows="5">{{ comment_form.body }}</textarea></label>
    <p class="hint">Plain text only. Comments are moderated. We don't ask for your email and don't store your IP address.</p>
    <button>Post comment</button>
  </form>
  {% endif %}
</section>
{% include "partials/foot" %}
