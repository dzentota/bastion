{% include "partials/head" %}
<article class="prose prose-wide">
  <h1>{{ t.tm_title }}</h1>
  <p>{{ t.tm_intro }}</p>
  <div class="tm tm-overview">{{ overview }}</div>
  <h2 id="s1">{{ t.tm_dfd_title }}</h2>
  <div class="tm tm-dfd">{{ dfd }}</div>
  <h2 id="s2">{{ t.tm_matrix_title }}</h2>
  <div class="tm tm-matrix">{{ matrix }}</div>
  <h2 id="s3">{{ t.tm_findings_title }}</h2>
  <div class="tm tm-findings">{{ findings }}</div>
</article>
{% include "partials/foot" %}
