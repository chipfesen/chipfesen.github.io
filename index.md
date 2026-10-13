---
layout: home
title: 首页
---

## 文章

<ul class="post-list">
{%- assign article_pages = site.pages | where: "layout", "post" -%}
{%- assign all_articles = article_pages | concat: site.posts | sort: "date" | reverse -%}
{%- for article in all_articles %}
  <li>
    <span class="post-meta">{{ article.date | date: "%b %-d, %Y" }}</span>
    <h3>
      <a class="post-link" href="{{ article.url | relative_url }}">{{ article.title | escape }}</a>
    </h3>
  </li>
{%- endfor %}
</ul>
