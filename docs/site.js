// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

(function () {
  "use strict";

  var root = document.documentElement;
  root.classList.add("js");

  var prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var revealItems = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
  if (revealItems.length > 0) {
    if (prefersReducedMotion || !("IntersectionObserver" in window)) {
      revealItems.forEach(function (item) {
        item.classList.add("is-visible");
      });
    } else {
      var revealObserver = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              entry.target.classList.add("is-visible");
              revealObserver.unobserve(entry.target);
            }
          });
        },
        { rootMargin: "0px 0px -12% 0px", threshold: 0.12 }
      );
      revealItems.forEach(function (item) {
        revealObserver.observe(item);
      });
    }
  }

  var navLinks = Array.prototype.slice.call(document.querySelectorAll(".site-nav a[href^='#']"));
  var sections = navLinks
    .map(function (link) {
      var id = link.getAttribute("href");
      var section = id ? document.querySelector(id) : null;
      return section ? { link: link, section: section } : null;
    })
    .filter(Boolean);

  if (sections.length > 0 && "IntersectionObserver" in window) {
    var activeObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) {
            return;
          }
          sections.forEach(function (pair) {
            pair.link.classList.toggle("is-active", pair.section === entry.target);
          });
        });
      },
      { rootMargin: "-35% 0px -55% 0px", threshold: 0.01 }
    );
    sections.forEach(function (pair) {
      activeObserver.observe(pair.section);
    });
  }

  var copyButtons = Array.prototype.slice.call(document.querySelectorAll("[data-copy]"));
  copyButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      var value = button.getAttribute("data-copy");
      if (!value || !navigator.clipboard || !navigator.clipboard.writeText) {
        return;
      }
      navigator.clipboard.writeText(value).then(
        function () {
          button.setAttribute("data-copied", "true");
          window.setTimeout(function () {
            button.removeAttribute("data-copied");
          }, 1400);
        },
        function () {}
      );
    });
  });
})();
