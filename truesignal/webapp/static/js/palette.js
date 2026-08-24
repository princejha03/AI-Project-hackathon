/* Ctrl/Cmd+K command palette: fetches the search index once, filters
   client-side (small dataset, demo/mock scale), keyboard-navigable. */
(function () {
  "use strict";

  var TYPE_META = {
    project: { label: "Project", icon: "▢" },
    finding: { label: "Finding", icon: "⚠" },
    override: { label: "Override", icon: "⚙" }
  };

  var overlay, input, list, hint;
  var index = null, indexPromise = null;
  var activeIdx = -1;
  var visibleItems = [];

  function build() {
    overlay = document.createElement("div");
    overlay.className = "palette-overlay";
    overlay.hidden = true;
    overlay.innerHTML =
      '<div class="palette-card" role="dialog" aria-label="Search">' +
      '  <div class="palette-input-row">' +
      '    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.8"/><path d="M20 20l-3.2-3.2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>' +
      '    <input type="text" class="palette-input" placeholder="Search projects, findings, overrides..." autocomplete="off">' +
      '    <span class="palette-esc">Esc</span>' +
      '  </div>' +
      '  <ul class="palette-results"></ul>' +
      '  <div class="palette-hint">Enter to open &middot; ↑↓ to navigate</div>' +
      '</div>';
    document.body.appendChild(overlay);
    input = overlay.querySelector(".palette-input");
    list = overlay.querySelector(".palette-results");
    hint = overlay.querySelector(".palette-hint");

    overlay.addEventListener("mousedown", function (e) {
      if (e.target === overlay) close();
    });
    input.addEventListener("input", function () { renderResults(input.value); });
    input.addEventListener("keydown", onKeydown);
  }

  function ensureIndex() {
    if (index) return Promise.resolve(index);
    if (!indexPromise) {
      indexPromise = fetch("/api/search-index").then(function (r) { return r.json(); }).then(function (data) {
        index = data;
        return index;
      }).catch(function () { index = []; return index; });
    }
    return indexPromise;
  }

  function score(item, q) {
    var label = item.label.toLowerCase(), sub = (item.sub || "").toLowerCase();
    if (label === q) return 100;
    if (label.indexOf(q) === 0) return 80;
    if (label.indexOf(q) !== -1) return 60;
    if (sub.indexOf(q) !== -1) return 30;
    return -1;
  }

  function renderResults(query) {
    var q = query.trim().toLowerCase();
    var items = index || [];
    var scored = items.map(function (it) { return { it: it, s: q ? score(it, q) : 1 }; })
      .filter(function (x) { return x.s >= 0; })
      .sort(function (a, b) { return b.s - a.s; })
      .slice(0, 30)
      .map(function (x) { return x.it; });
    visibleItems = scored;
    activeIdx = scored.length ? 0 : -1;
    if (!scored.length) {
      list.innerHTML = '<li class="palette-empty">' + (q ? "No matches for “" + escapeHTML(query) + "”" : "Type to search across every project") + "</li>";
      return;
    }
    list.innerHTML = scored.map(function (it, i) {
      var meta = TYPE_META[it.type] || { label: it.type, icon: "•" };
      return '<li class="palette-item' + (i === 0 ? " active" : "") + '" data-idx="' + i + '" data-url="' + escapeHTML(it.url) + '">' +
        '<span class="palette-item-icon">' + meta.icon + "</span>" +
        '<span class="palette-item-body"><span class="palette-item-label">' + escapeHTML(it.label) + "</span>" +
        '<span class="palette-item-sub">' + escapeHTML(it.sub || "") + "</span></span>" +
        '<span class="palette-item-type">' + meta.label + "</span></li>";
    }).join("");
    Array.prototype.forEach.call(list.querySelectorAll(".palette-item"), function (li) {
      li.addEventListener("mouseenter", function () { setActive(parseInt(li.dataset.idx, 10)); });
      li.addEventListener("click", function () { navigate(li.dataset.url); });
    });
  }

  function escapeHTML(s) {
    return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }

  function setActive(i) {
    activeIdx = i;
    Array.prototype.forEach.call(list.querySelectorAll(".palette-item"), function (li) {
      li.classList.toggle("active", parseInt(li.dataset.idx, 10) === i);
    });
    var el = list.querySelector('.palette-item[data-idx="' + i + '"]');
    if (el) el.scrollIntoView({ block: "nearest" });
  }

  function navigate(url) {
    window.location.href = url;
  }

  function onKeydown(e) {
    if (e.key === "Escape") { close(); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); if (visibleItems.length) setActive((activeIdx + 1) % visibleItems.length); return; }
    if (e.key === "ArrowUp") { e.preventDefault(); if (visibleItems.length) setActive((activeIdx - 1 + visibleItems.length) % visibleItems.length); return; }
    if (e.key === "Enter") {
      e.preventDefault();
      var item = visibleItems[activeIdx];
      if (item) navigate(item.url);
    }
  }

  function open() {
    if (!overlay) build();
    overlay.hidden = false;
    input.value = "";
    ensureIndex().then(function () { renderResults(""); });
    setTimeout(function () { input.focus(); }, 0);
  }

  function close() {
    if (overlay) overlay.hidden = true;
  }

  document.addEventListener("keydown", function (e) {
    var isK = e.key === "k" || e.key === "K";
    if ((e.metaKey || e.ctrlKey) && isK) {
      e.preventDefault();
      open();
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    var trigger = document.getElementById("search-trigger");
    if (trigger) trigger.addEventListener("click", open);
  });
})();
