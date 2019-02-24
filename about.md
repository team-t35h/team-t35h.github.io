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

      {% if member.job %}
        <li>Job/Studies: {{ member.job }}</li>
      {% endif %}

      {% if member.specialties %}
        <li>Specialties: {{ member.specialties }}</li>
      {% endif %}

      {% if member.github %}
        <li>Github: <a href="{{ member.github }}">
          {{ member.github}}
        </a></li>
      {% endif %}

      {% if member.linkedin %}
        <li>Linkedin: <a href="{{ member.linkedin }}">
          {{ member.linkedin}}
        </a></li>
      {% endif %}

      {% if member.rootme %}
        <li>Rootme: <a href="{{ member.rootme }}">
          {{ member.rootme}}
        </a></li>
      {% endif %}

      {% if member.content %}
        <li>Description: {{ member.content | markdownify }}</li>
      {% endif %}

    </ul>
  {% endfor %}
</section>
