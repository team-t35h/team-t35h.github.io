---
layout: page
title: About
---
<section>
  {% for member in site.members %}
    <div>
      <img class="about_logo" src="{{ member.logo }}" />
      <h2 class="about_title">{{ member.name }}</h2>
    </div>
    <ul>
      <li>Job: {{ member.job }}</li>
      <li>Specialties: {{ member.specialties }}</li>
      <li>Description: {{ member.content | markdownify }}</li>
    </ul>
  {% endfor %}
</section>
