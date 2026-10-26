// SPDX-License-Identifier: AGPL-3.0-only
// The picker between the site's two designs while the owner chooses one:
// it sets data-skin on <html> and keeps the choice in this browser only.
(function () {
  var root = document.documentElement, key = "cbb-skin";
  try {
    var saved = localStorage.getItem(key);
    if (saved === "slate" || saved === "deco") root.dataset.skin = saved;
  } catch (e) {}
  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector(".skin");
    if (!button) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      var next = root.dataset.skin === "deco" ? "slate" : "deco";
      root.dataset.skin = next;
      try { localStorage.setItem(key, next); } catch (e) {}
    });
  });
})();
