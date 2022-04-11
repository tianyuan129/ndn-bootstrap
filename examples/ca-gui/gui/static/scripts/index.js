/* Exact match */
function do_menu_search() {
  var input = document.getElementById("menu_search");
  var filter = input.value.toUpperCase();
  var menu = document.getElementById("div_menu_items");
  var buttons = menu.getElementsByTagName("input");

  for (var i = 0; i < buttons.length; i++) {
    if (buttons[i].value.toUpperCase().indexOf(filter) > -1) {
      buttons[i].style.display = "";
    } else {
      buttons[i].style.display = "none";
    }
  }
}

/* Change content by resetting iFrame src */
function set_content(url) {
  document.getElementById('content_frame').src = url;
}