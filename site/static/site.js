// SPDX-License-Identifier: AGPL-3.0-only
//
// The site's one script of its own, small enough to run before the page is
// drawn: it puts the reader's theme on <html> at once, so a light page
// never flashes dark, then wires the theme button and, on the download
// page, points at the reader's own system. Without it the site works as
// before: the theme follows the system and every way to download is shown.
"use strict";
(function () {
  var root = document.documentElement;
  var KEY = "cbb-theme"; // "light" or "dark"; nothing stored means "as the system"
  function stored() {
    try { return localStorage.getItem(KEY) || ""; } catch (e) { return ""; }
  }
  function apply(choice) {
    if (choice === "light" || choice === "dark") root.setAttribute("data-theme", choice);
    else root.removeAttribute("data-theme");
  }
  apply(stored());

  // The reader's system, from the browser: "android", "iphone", "windows",
  // "mac", "linux", or "" when it cannot tell.
  function system() {
    var ua = navigator.userAgent || "";
    var p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    if (/android/i.test(ua)) return "android";
    if (/iphone|ipad|ipod/i.test(ua) || (/mac/i.test(p) && navigator.maxTouchPoints > 1)) return "iphone";
    if (/win/i.test(p) || /windows/i.test(ua)) return "windows";
    if (/mac/i.test(p)) return "mac";
    if (/linux|x11|cros/i.test(p + ua)) return "linux";
    return "";
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector(".theme");
    if (button) {
      var order = ["", "light", "dark"];
      var show = function (choice) {
        button.setAttribute("data-choice", choice || "auto");
        var label = button.getAttribute("data-" + (choice || "auto"));
        button.setAttribute("aria-label", label);
        button.title = label;
      };
      show(stored());
      button.hidden = false;
      button.addEventListener("click", function () {
        var next = order[(order.indexOf(stored()) + 1) % order.length];
        try {
          if (next) localStorage.setItem(KEY, next); else localStorage.removeItem(KEY);
        } catch (e) { /* a browser that keeps nothing still switches for this page */ }
        apply(next);
        show(next);
      });
    }

    // The download page: the reader's own system first, with its own button.
    var os = system();
    var pick = os && document.querySelector('.pick [data-os~="' + os + '"]');
    if (pick) {
      pick.hidden = false;
      pick.parentNode.hidden = false;
      var card = document.querySelector('.card[data-os~="' + os + '"]');
      if (card) {
        card.classList.add("mine");
        card.parentNode.insertBefore(card, card.parentNode.firstElementChild);
      }
    }
  });
})();
