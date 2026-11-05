// Live dashboard refresh. Polls the session-authed JSON endpoints and updates
// the severity counts and the recent-activity table without a full reload.
(function () {
  "use strict";

  var SEV = ["critical", "warning", "notice", "info"];

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function row(e) {
    return (
      '<tr class="sev-row-' + esc(e.severity) + '">' +
      '<td class="mono">' + esc(e.ts) + "</td>" +
      '<td><span class="src">' + esc(e.source) + "</span></td>" +
      "<td>" + esc(e.monitor) + "</td>" +
      '<td><span class="sev sev-' + esc(e.severity) + '">' + esc(e.severity) + "</span></td>" +
      "<td>" + esc(e.action) + "</td>" +
      '<td class="mono">' + esc(e.target) + "</td>" +
      '<td class="mono muted">' + esc(e.detail) + "</td>" +
      "</tr>"
    );
  }

  function refresh(tbody, counts) {
    fetch("/api/events.json?limit=25", { headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !tbody) return;
        if (!data.events.length) {
          tbody.innerHTML = '<tr><td colspan="7" class="muted">No events recorded yet.</td></tr>';
          return;
        }
        tbody.innerHTML = data.events.map(row).join("");
      })
      .catch(function () {});

    if (counts) {
      fetch("/api/status.json", { headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) return;
          SEV.forEach(function (s) {
            var el = counts.querySelector('[data-count="' + s + '"]');
            if (el) el.textContent = data.counts[s] || 0;
          });
        })
        .catch(function () {});
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var tbody = document.querySelector("#live-events tbody");
    var counts = document.querySelector("#live-counts");
    var toggle = document.querySelector("#auto-refresh");
    if (!tbody) return;

    var timer = null;
    function start() { timer = setInterval(function () { refresh(tbody, counts); }, 5000); }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }

    if (toggle) {
      toggle.addEventListener("change", function () { toggle.checked ? start() : stop(); });
      if (toggle.checked) start();
    } else {
      start();
    }
  });
})();
