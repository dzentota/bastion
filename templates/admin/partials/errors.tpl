{% if errors %}<ul class="errors" role="alert">{% each errors as e %}<li>{{ e }}</li>{% endeach %}</ul>{% endif %}{% if error %}<p class="errors" role="alert">{{ error }}</p>{% endif %}
