<!doctype html>
<html lang="{% if ui_lang %}{{ ui_lang | attr }}{% else %}en{% endif %}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>{{ t.admin_title }}</title>
<link rel="stylesheet" href="/assets/tokens.css">
<link rel="stylesheet" href="/assets/admin.css">
</head>
<body{% if staff %} class="shell"{% endif %}>
<a class="skip" href="#main">{{ t.skip_to_content }}</a>
{% if staff %}
<header class="topbar">
  <a class="mark" href="/admin">{% include "partials/mark" %}<span>Bastion</span></a>
  <div class="who">
    <span>{{ t.signed_in_as }} <strong>{{ staff.name }}</strong></span>
    {% if ui_languages %}<form method="post" action="/admin/locale" class="ui-lang"><input type="hidden" name="_token" value="{{ csrf | attr }}">{% each ui_languages as l %}{% if l.current %}<strong aria-current="true">{{ l.code }}</strong>{% else %}<button class="link" name="lang" value="{{ l.code | attr }}" lang="{{ l.code | attr }}">{{ l.code }}</button>{% endif %} {% endeach %}</form>{% endif %}
    <form method="post" action="/admin/logout"><input type="hidden" name="_token" value="{{ csrf | attr }}"><button class="link">{{ t.sign_out }}</button></form>
  </div>
</header>
<nav class="sidenav" aria-label="{{ t.admin_nav | attr }}">
  <a href="/admin"{% if staff.nav.content %} aria-current="page"{% endif %}>{{ t.content }}</a>
  <a href="/admin/media"{% if staff.nav.media %} aria-current="page"{% endif %}>{{ t.media_library }}</a>
  <a href="/admin/comments"{% if staff.nav.comments %} aria-current="page"{% endif %}>{{ t.comments }}</a>
  <a href="/admin/menu"{% if staff.nav.menu %} aria-current="page"{% endif %}>{{ t.site_menu }}</a>
  <a href="/admin/audit"{% if staff.nav.audit %} aria-current="page"{% endif %}>{{ t.audit }}</a>
  <a href="/admin/extensions"{% if staff.nav.extensions %} aria-current="page"{% endif %}>{{ t.extensions }}</a>
  <a href="/admin/database"{% if staff.nav.database %} aria-current="page"{% endif %}>{{ t.database }}</a>
</nav>
{% endif %}
<main class="wrap" id="main">
{% if not staff %}<p class="solo-mark">{% include "partials/mark" %}<span>Bastion</span></p>{% endif %}
