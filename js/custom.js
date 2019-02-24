function showDiv(id_name) {
  var data = document.getElementById(id_name);
  if (data.style.display != 'block') { data.style.display = 'block' }
  else { data.style.display = 'none' }
}
