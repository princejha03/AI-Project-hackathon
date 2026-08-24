/* Dependency-free inline-SVG charts. Colors are resolved from the page's
   CSS custom properties (via a colorKey lookup) so charts always match the
   active light/dark theme without the server needing to know about colors. */
(function () {
  "use strict";

  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function palette() {
    return {
      critical: cssVar("--sev-critical", "#a91d1d"),
      high: cssVar("--sev-high", "#b1550f"),
      medium: cssVar("--sev-medium", "#92650a"),
      low: cssVar("--sev-low", "#2f6d3a"),
      info: cssVar("--sev-info", "#3552b5"),
      success: cssVar("--success", "#15803d"),
      danger: cssVar("--danger", "#b42318"),
      warning: cssVar("--warning", "#b45309"),
      accent: cssVar("--accent", "#4338ca"),
      faint: cssVar("--text-faint", "#8790a0"),
      border: cssVar("--border-strong", "#cdd2db")
    };
  }

  function color(key) {
    return palette()[key] || palette().faint;
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function donutSVG(segments, opts) {
    opts = opts || {};
    var size = opts.size || 132, thickness = opts.thickness || 16;
    var r = (size - thickness) / 2, cx = size / 2, cy = size / 2;
    var circumference = 2 * Math.PI * r;
    var total = segments.reduce(function (s, x) { return s + x.value; }, 0);
    if (!total) {
      return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '">' +
        '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + color("border") + '" stroke-width="' + thickness + '"></circle>' +
        '<text x="' + cx + '" y="' + (cy + 5) + '" text-anchor="middle" class="chart-total">0</text></svg>';
    }
    var offset = 0, parts = "";
    segments.forEach(function (seg) {
      if (!seg.value) return;
      var frac = seg.value / total;
      var len = frac * circumference;
      parts += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + color(seg.colorKey) +
        '" stroke-width="' + thickness + '" stroke-dasharray="' + len + ' ' + (circumference - len) +
        '" stroke-dashoffset="' + (-offset) + '" transform="rotate(-90 ' + cx + ' ' + cy + ')">' +
        "<title>" + esc(seg.label) + ": " + seg.value + "</title></circle>";
      offset += len;
    });
    return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '">' + parts +
      '<text x="' + cx + '" y="' + (cy - 3) + '" text-anchor="middle" class="chart-total">' + total + "</text>" +
      '<text x="' + cx + '" y="' + (cy + 15) + '" text-anchor="middle" class="chart-total-label">total</text></svg>';
  }

  function legendHTML(segments) {
    var total = segments.reduce(function (s, x) { return s + x.value; }, 0) || 1;
    return '<ul class="chart-legend">' + segments.map(function (seg) {
      var pct = Math.round((seg.value / total) * 100);
      return '<li><span class="chart-swatch" style="background:' + color(seg.colorKey) + '"></span>' +
        '<span class="chart-legend-label">' + esc(seg.label) + '</span>' +
        '<span class="chart-legend-value">' + seg.value + (seg.value ? " (" + pct + "%)" : "") + "</span></li>";
    }).join("") + "</ul>";
  }

  function barsSVG(series, opts) {
    opts = opts || {};
    var w = opts.width || 320, h = opts.height || 150, pad = 26;
    var max = Math.max.apply(null, series.map(function (s) { return s.value; }).concat([1]));
    var bw = (w - pad * 2) / series.length;
    var bars = series.map(function (s, i) {
      var bh = max ? (s.value / max) * (h - pad * 1.6) : 0;
      var x = pad + i * bw + bw * 0.16;
      var y = h - pad - bh;
      var bwidth = bw * 0.68;
      return '<rect x="' + x + '" y="' + y + '" width="' + bwidth + '" height="' + Math.max(bh, s.value ? 2 : 0) +
        '" rx="3" fill="' + color(s.colorKey) + '"><title>' + esc(s.label) + ": " + s.value + "</title></rect>" +
        '<text x="' + (x + bwidth / 2) + '" y="' + (h - pad + 15) + '" text-anchor="middle" class="chart-axis-label">' + esc(s.label) + "</text>" +
        (s.value ? '<text x="' + (x + bwidth / 2) + '" y="' + (y - 6) + '" text-anchor="middle" class="chart-bar-value">' + s.value + "</text>" : "");
    }).join("");
    return '<svg viewBox="0 0 ' + w + " " + h + '" width="100%" height="' + h + '" preserveAspectRatio="xMidYMid meet">' + bars + "</svg>";
  }

  function groupedBarsSVG(groups, opts) {
    opts = opts || {};
    if (!groups.length) return '<p class="faint small">No project data yet.</p>';
    var w = opts.width || 640, h = opts.height || 170, pad = 30;
    var keys = opts.keys || [];
    var max = 1;
    groups.forEach(function (g) { keys.forEach(function (k) { max = Math.max(max, g[k.key] || 0); }); });
    var gw = (w - pad * 2) / groups.length;
    var barW = Math.min(18, (gw * 0.7) / keys.length);
    var svg = "";
    groups.forEach(function (g, gi) {
      var groupX = pad + gi * gw + gw / 2 - (barW * keys.length) / 2;
      keys.forEach(function (k, ki) {
        var val = g[k.key] || 0;
        var bh = (val / max) * (h - pad * 1.7);
        var x = groupX + ki * barW;
        var y = h - pad - bh;
        svg += '<rect x="' + x + '" y="' + y + '" width="' + (barW - 3) + '" height="' + Math.max(bh, val ? 2 : 0) +
          '" rx="2" fill="' + color(k.colorKey) + '"><title>' + esc(g.label) + " · " + esc(k.key) + ": " + val + "</title></rect>";
      });
      svg += '<text x="' + (pad + gi * gw + gw / 2) + '" y="' + (h - pad + 16) + '" text-anchor="middle" class="chart-axis-label">' + esc(g.label) + "</text>";
    });
    return '<svg viewBox="0 0 ' + w + " " + h + '" width="100%" height="' + h + '" preserveAspectRatio="xMidYMid meet">' + svg + "</svg>";
  }

  function trendSVG(points, opts) {
    opts = opts || {};
    var w = opts.width || 600, h = opts.height || 84, pad = 6;
    var max = Math.max.apply(null, points.map(function (p) { return p.value; }).concat([1]));
    var stepX = (w - pad * 2) / Math.max(points.length - 1, 1);
    var coords = points.map(function (p, i) {
      return [pad + i * stepX, h - pad - (p.value / max) * (h - pad * 2)];
    });
    var line = coords.map(function (c, i) { return (i === 0 ? "M" : "L") + c[0] + "," + c[1]; }).join(" ");
    var last = coords[coords.length - 1], first = coords[0];
    var area = line + " L" + last[0] + "," + (h - pad) + " L" + first[0] + "," + (h - pad) + " Z";
    var dots = points.map(function (p, i) {
      if (!p.value) return "";
      return '<circle cx="' + coords[i][0] + '" cy="' + coords[i][1] + '" r="2.4" fill="' + color("accent") + '"><title>' + esc(p.date) + ": " + p.value + "</title></circle>";
    }).join("");
    return '<svg viewBox="0 0 ' + w + " " + h + '" width="100%" height="' + h + '" preserveAspectRatio="none">' +
      '<path d="' + area + '" fill="' + color("accent") + '" opacity="0.14"></path>' +
      '<path d="' + line + '" fill="none" stroke="' + color("accent") + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"></path>' +
      dots + "</svg>";
  }

  function signedTrendSVG(points, opts) {
    opts = opts || {};
    var w = opts.width || 320, h = opts.height || 70, pad = 6;
    if (!points || !points.length) {
      return '<p class="faint small">No audit decisions recorded yet for this signature.</p>';
    }
    var values = points.map(function (p) { return p.adjustment; });
    var min = Math.min.apply(null, values.concat([0]));
    var max = Math.max.apply(null, values.concat([0]));
    if (min === max) { min -= 0.01; max += 0.01; }
    function toY(v) { return h - pad - ((v - min) / (max - min)) * (h - pad * 2); }
    var stepX = (w - pad * 2) / Math.max(points.length - 1, 1);
    var coords = points.map(function (p, i) { return [pad + i * stepX, toY(p.adjustment)]; });
    var zeroY = toY(0);
    var line = coords.map(function (c, i) { return (i === 0 ? "M" : "L") + c[0] + "," + c[1]; }).join(" ");
    var first = coords[0], last = coords[coords.length - 1];
    var area = line + " L" + last[0] + "," + zeroY + " L" + first[0] + "," + zeroY + " Z";
    var lineColor = color(values[values.length - 1] >= 0 ? "success" : "danger");
    var dots = points.map(function (p, i) {
      return '<circle cx="' + coords[i][0] + '" cy="' + coords[i][1] + '" r="2.4" fill="' + lineColor + '">' +
        "<title>" + esc((p.timestamp || "").slice(0, 19)) + " · " + esc(p.outcome) + " → " +
        (p.adjustment >= 0 ? "+" : "") + p.adjustment.toFixed(3) + "</title></circle>";
    }).join("");
    return '<svg viewBox="0 0 ' + w + " " + h + '" width="100%" height="' + h + '" preserveAspectRatio="none">' +
      '<line x1="' + pad + '" y1="' + zeroY + '" x2="' + (w - pad) + '" y2="' + zeroY +
      '" stroke="' + color("border") + '" stroke-width="1" stroke-dasharray="3,3"></line>' +
      '<path d="' + area + '" fill="' + lineColor + '" opacity="0.14"></path>' +
      '<path d="' + line + '" fill="none" stroke="' + lineColor + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"></path>' +
      dots + "</svg>";
  }

  function gaugeSVG(pct, opts) {
    opts = opts || {};
    var size = opts.size || 148, thickness = opts.thickness || 14;
    var r = (size - thickness) / 2, cx = size / 2, cy = size / 2;
    var circumference = 2 * Math.PI * r;
    var clamped = Math.max(0, Math.min(100, pct || 0));
    var offset = circumference * (1 - clamped / 100);
    var fillColor = clamped >= 50 ? color("success") : clamped >= 20 ? color("warning") : color("faint");
    return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '">' +
      '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + color("border") +
        '" stroke-width="' + thickness + '"></circle>' +
      '<circle class="gauge-fill" cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + fillColor +
        '" stroke-width="' + thickness + '" stroke-linecap="round" stroke-dasharray="' + circumference +
        '" stroke-dashoffset="' + circumference + '" transform="rotate(-90 ' + cx + ' ' + cy +
        ')" data-target-offset="' + offset + '"></circle>' +
      '<text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" class="chart-total">' + clamped + '%</text>' +
      '<text x="' + cx + '" y="' + (cy + 16) + '" text-anchor="middle" class="chart-total-label">' +
        esc(opts.label || "noise eliminated") + "</text></svg>";
  }

  var registry = [];

  function renderOne(entry) {
    var el = document.getElementById(entry.target);
    if (!el) return;
    if (entry.type === "donut") {
      el.innerHTML = '<div class="chart-donut-row">' + donutSVG(entry.data.segments, entry.data.opts) +
        legendHTML(entry.data.segments) + "</div>";
    } else if (entry.type === "bars") {
      el.innerHTML = barsSVG(entry.data.series, entry.data.opts);
    } else if (entry.type === "grouped-bars") {
      el.innerHTML = groupedBarsSVG(entry.data.groups, entry.data);
    } else if (entry.type === "trend") {
      el.innerHTML = trendSVG(entry.data.points, entry.data.opts);
    } else if (entry.type === "signed-trend") {
      el.innerHTML = signedTrendSVG(entry.data.points, entry.data.opts);
    } else if (entry.type === "gauge") {
      el.innerHTML = gaugeSVG(entry.data.pct, entry.data.opts);
      var fill = el.querySelector(".gauge-fill");
      if (fill) {
        var target = fill.getAttribute("data-target-offset");
        // Two rAFs so the browser paints the 0%-filled state first, then
        // animates the CSS transition to the real value instead of the two
        // states collapsing into a single, un-animated paint.
        requestAnimationFrame(function () {
          requestAnimationFrame(function () { fill.style.strokeDashoffset = target; });
        });
      }
    }
  }

  function renderAll() {
    registry.forEach(renderOne);
  }

  function init() {
    document.querySelectorAll("script[data-chart-for]").forEach(function (script) {
      var target = script.getAttribute("data-chart-for");
      var type = script.getAttribute("data-chart-type");
      var data;
      try { data = JSON.parse(script.textContent); } catch (e) { return; }
      registry.push({ target: target, type: type, data: data });
    });
    renderAll();
  }

  document.addEventListener("DOMContentLoaded", init);
  window.addEventListener("truesignal:theme", renderAll);
})();
