<!doctype html>
<html lang="{% if site.lang %}{{ site.lang | attr }}{% else %}en{% endif %}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% if entry %}{{ entry.title }} — {% endif %}{{ site.name }}</title>
<link rel="stylesheet" href="/assets/tokens.css">
<link rel="stylesheet" href="/assets/theme.css">
{% if preview %}<meta name="robots" content="noindex, nofollow">{% endif %}
{% each site.alternates as a %}<link rel="alternate" hreflang="{{ a.lang | attr }}" href="{{ a.url | url }}">
{% endeach %}
</head>
<body>
<a class="skip" href="#main">{{ t.skip_to_content }}</a>
<header class="site">
  <a class="mark" href="{% if site.home %}{{ site.home | url }}{% else %}/{% endif %}">{% include "partials/mark" %}<span>{{ site.name }}</span></a>
  {% if site.menu %}<nav class="menu" aria-label="{{ t.site_menu | attr }}">{% each site.menu as item %}<a href="{{ item.url | url }}">{{ item.title }}</a>{% endeach %}</nav>{% endif %}
  {% if site.languages %}<nav class="languages" aria-label="{{ t.language | attr }}">{% each site.languages as l %}{% if l.current %}<strong aria-current="true">{{ l.lang }}</strong>{% else %}<a href="{{ l.url | url }}" hreflang="{{ l.lang | attr }}" lang="{{ l.lang | attr }}">{{ l.lang }}</a>{% endif %}{% endeach %}</nav>{% endif %}
</header>
{% if preview %}<p class="preview-banner" role="status">{{ t.preview_banner }}</p>{% endif %}
<main id="main">
