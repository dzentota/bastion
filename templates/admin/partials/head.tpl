<!doctype html>
<html lang="{% if ui_lang %}{{ ui_lang | attr }}{% else %}en{% endif %}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>{{ t.admin_title }}</title>
<link rel="stylesheet" href="/assets/admin.css">
</head>
<body>
<main class="wrap">
