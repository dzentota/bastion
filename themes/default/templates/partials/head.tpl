<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% if entry %}{{ entry.title }} — {% endif %}{{ site.name }}</title>
<link rel="stylesheet" href="/assets/theme.css">
</head>
<body>
<header class="site"><a href="/">{{ site.name }}</a>{% if site.menu %}<nav class="menu" aria-label="Site">{% each site.menu as item %}<a href="{{ item.url | url }}">{{ item.title }}</a>{% endeach %}</nav>{% endif %}</header>
<main>
