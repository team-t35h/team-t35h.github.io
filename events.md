---
layout: page
title: Events
---
<section>
  <ul>
  {% for event in site.events %}
    <li>
    <h2 class="event_title" onclick="showDiv('{{ event.name }}')">
      {{ event.rank }} at {{ event.name }} ({{ event.date-string }})
    </h2>

    <div id="{{ event.name }}" style='display: none'>
    {% if event.image-team %}
      <h3 class="event_subtitle">T35H Team:</h3>
      <img src="{{ event.images-path }}{{ event.image-team }}" />
    {% endif %}

    {{ event.content | markdownify }}

    {% if event.image-group %}
      <h3 class="event_subtitle">Teams:</h3>
      <img src="{{ event.images-path }}{{ event.image-group }}" />
    {% endif %}

    {% if event.image-scoreboard %}
      <h3 class="event_subtitle">Scoreboard:</h3>
      <img src="{{ event.images-path }}{{ event.image-scoreboard }}" />
    {% endif %}
    </div>

    </li>

  {% endfor %}
  </ul>
</section>
