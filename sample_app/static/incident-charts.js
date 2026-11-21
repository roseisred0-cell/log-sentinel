// The "Thong ke su co" (du lieu /api/stats):
//   - Cot xep chong theo muc do: CRITICAL (do, duoi cung) / HIGH (cam) / Khac (xam). Mau trang thai, luon kem chu thich chu.
//   - Ma tran nhiet luat x thoi gian: mot sac ho phach (nhat = it, dam = nhieu), co so trong o.
//     Khac sac voi cot de o dam khong bi hieu nham la CRITICAL.
//   IncidentCharts.render(stats, {hourly, matrix, table, note, legend, tip})  - ve vao cac phan tu DOM
//   IncidentCharts.bucket(count, max) -> 0..5                                 - muc dam cua o (ham thuan, co test)
// Chi dung createElement/createElementNS + textContent (khong innerHTML): ten luat den tu du lieu.
// Mau da kiem tra bang validate_palette.js cho nen sang va toi (xem console.css).
(function (root) {
  "use strict";
  var SVG = "http://www.w3.org/2000/svg";
  var STACK = ["CRITICAL", "HIGH", "Khác"];     // thu tu xep chong co dinh (mau di theo muc do, khong theo thu hang)
  var STACK_CLASS = { "CRITICAL": "sev-critical", "HIGH": "sev-high", "Khác": "sev-other" };

  function bucket(count, max) {
    if (!(count > 0) || !(max > 0)) return 0;
    return Math.max(1, Math.min(5, Math.ceil((count / max) * 5)));
  }

  function pad(n) { return String(n).padStart(2, "0"); }

  // Nhan cua o thu i. O theo gio: "14:00–15:00"; o theo ngay: "20/11".
  function slotLabel(stats, i, short) {
    var d = new Date((stats.window_start + i * stats.slot_seconds) * 1000);
    if (stats.slot_seconds >= 86400) return pad(d.getDate()) + "/" + pad(d.getMonth() + 1);
    var h = pad(d.getHours());
    if (short) return h + "h";
    return h + ":00–" + pad(new Date(d.getTime() + 3600 * 1000).getHours()) + ":00";
  }

  // Cach bao nhieu o thi ghi nhan truc: 24 gio -> moi 3 gio, 7 ngay -> moi ngay, 30 ngay -> moi 5 ngay.
  function tickEvery(stats) { return stats.slots <= 7 ? 1 : stats.slots <= 24 ? 3 : 5; }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  function svg(tag, attrs, text) {
    var e = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = String(text);
    return e;
  }

  // ------------------------------------------------------------- chu thich noi
  function attachTip(target, tip, text) {
    function show(ev) {
      tip.textContent = text;
      tip.hidden = false;
      var x = Math.min(ev.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
      var y = ev.clientY - tip.offsetHeight - 12;
      tip.style.left = Math.max(8, x) + "px";
      tip.style.top = (y < 8 ? ev.clientY + 18 : y) + "px";
    }
    target.addEventListener("mousemove", show);
    target.addEventListener("mouseenter", show);
    target.addEventListener("mouseleave", function () { tip.hidden = true; });
  }

  function present(stats) {
    return STACK.filter(function (k) { return stats.series[k] && stats.series[k].some(function (v) { return v > 0; }); });
  }

  function renderLegend(box, stats) {
    box.replaceChildren();
    present(stats).forEach(function (k) {
      var item = el("span", "legend-item");
      item.appendChild(el("span", "legend-swatch " + STACK_CLASS[k]));
      item.appendChild(document.createTextNode(k === "Khác" ? "Mức khác" : k));
      box.appendChild(item);
    });
  }

  // Duong vien cot: chan vuong tren truc, dinh bo tron 4px (chi doan tren cung).
  function columnPath(x, w, yTop, yBottom, roundTop) {
    var r = roundTop ? Math.min(4, w / 2, yBottom - yTop) : 0;
    return "M" + x + "," + yBottom + "V" + (yTop + r) +
      (r ? "Q" + x + "," + yTop + " " + (x + r) + "," + yTop : "") + "H" + (x + w - r) +
      (r ? "Q" + (x + w) + "," + yTop + " " + (x + w) + "," + (yTop + r) : "") + "V" + yBottom + "Z";
  }

  // ------------------------------------------------- cot xep chong theo muc do
  function renderColumns(box, stats, tip) {
    // ve dung be rong that cua khung (khong co gian viewBox) de chu tren truc luon 11px
    var W = Math.max(320, Math.round(box.clientWidth || 720)), H = 180, padL = 30, padR = 6, padT = 20, padB = 22;
    var n = stats.slots, max = Math.max(1, stats.max_slot);
    var plotW = W - padL - padR, plotH = H - padT - padB, slot = plotW / n;
    var barW = Math.max(3, Math.min(slot - 2, 48)), GAP = 2;
    var base = padT + plotH, every = tickEvery(stats), layers = present(stats);
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, class: "viz-svg", role: "img",
                         "aria-label": "Số sự cố theo mức độ, tổng " + stats.total });
    s.appendChild(svg("line", { x1: padL, x2: W - padR, y1: padT, y2: padT, class: "viz-grid" }));
    s.appendChild(svg("line", { x1: padL, x2: W - padR, y1: base, y2: base, class: "viz-axis" }));
    s.appendChild(svg("text", { x: padL - 6, y: padT + 4, class: "viz-tick", "text-anchor": "end" }, max));
    s.appendChild(svg("text", { x: padL - 6, y: base + 4, class: "viz-tick", "text-anchor": "end" }, 0));
    var peak = stats.by_slot.indexOf(stats.max_slot);

    for (var i = 0; i < n; i++) {
      var x = padL + i * slot + (slot - barW) / 2, y = base, parts = [];
      var top = -1;
      layers.forEach(function (k, idx) { if (stats.series[k][i] > 0) top = idx; });
      layers.forEach(function (k, idx) {
        var v = stats.series[k][i];
        if (!v) return;
        var h = Math.max(2, (v / max) * plotH);
        var yTop = y - h;
        s.appendChild(svg("path", { class: "viz-bar " + STACK_CLASS[k], d: columnPath(x, barW, yTop, y, idx === top) }));
        y = yTop - GAP;                       // khe 2px mau nen giua cac doan
        parts.push(k + " " + v);
      });
      if (i === peak && stats.max_slot > 0) {
        s.appendChild(svg("text", { x: x + barW / 2, y: y - 3, class: "viz-value", "text-anchor": "middle" }, stats.max_slot));
      }
      if (i % every === 0) {
        s.appendChild(svg("text", { x: x + barW / 2, y: H - 6, class: "viz-tick", "text-anchor": "middle" },
                          slotLabel(stats, i, true)));
      }
      var hit = svg("rect", { x: padL + i * slot, y: padT, width: slot, height: plotH, class: "viz-hit" });
      attachTip(hit, tip, slotLabel(stats, i) + " · " + stats.by_slot[i] + " sự cố" +
                (parts.length ? " (" + parts.join(", ") + ")" : ""));
      s.appendChild(hit);
    }
    box.replaceChildren(s);
  }

  // ------------------------------------------------- ma tran luat x thoi gian
  function renderMatrix(box, stats, tip) {
    var n = stats.slots, every = tickEvery(stats);
    var grid = el("div", "heat");
    grid.style.gridTemplateColumns = "minmax(120px, max-content) repeat(" + n + ", minmax(14px, 1fr)) 44px";
    grid.setAttribute("role", "table");
    grid.setAttribute("aria-label", "Ma trận luật theo thời gian");

    grid.appendChild(el("span", "heat-head", "Luật"));
    for (var i = 0; i < n; i++) grid.appendChild(el("span", "heat-head heat-hour", i % every === 0 ? slotLabel(stats, i, true) : ""));
    grid.appendChild(el("span", "heat-head heat-total", "Tổng"));

    stats.rules.forEach(function (row) {
      grid.appendChild(el("span", "heat-rule", row.rule));
      row.counts.forEach(function (count, j) {
        var cell = el("span", "heat-cell c" + bucket(count, stats.max_cell), count > 0 ? count : null);
        var text = row.rule + " · " + slotLabel(stats, j) + " · " + count + " sự cố";
        cell.setAttribute("aria-label", text);
        attachTip(cell, tip, text);
        grid.appendChild(cell);
      });
      grid.appendChild(el("span", "heat-total", row.total));
    });

    var legend = el("div", "heat-legend");
    legend.appendChild(el("span", null, "Số sự cố: ít"));
    for (var b = 1; b <= 5; b++) legend.appendChild(el("span", "heat-cell c" + b));
    legend.appendChild(el("span", null, "nhiều · ô trống = 0"));
    box.replaceChildren(grid, legend);
  }

  // ------------------------------------------------- bang so (cho trinh doc man hinh / in)
  function renderTable(table, stats) {
    var body = document.createElement("tbody");
    stats.rules.forEach(function (row) {
      var tr = document.createElement("tr");
      tr.appendChild(el("td", "mono", row.rule));
      tr.appendChild(el("td", null, row.total));
      tr.appendChild(el("td", null, slotLabel(stats, row.counts.indexOf(Math.max.apply(null, row.counts)))));
      body.appendChild(tr);
    });
    var head = document.createElement("thead"), hr = document.createElement("tr");
    ["Luật", "Số sự cố", stats.slot_seconds >= 86400 ? "Ngày nhiều nhất" : "Giờ nhiều nhất"]
      .forEach(function (h) { hr.appendChild(el("th", null, h)); });
    head.appendChild(hr);
    table.replaceChildren(head, body);
  }

  var RANGE_TEXT = { "24h": "24 giờ qua", "7d": "7 ngày qua", "30d": "30 ngày qua" };
  var last = null, resizeTimer = null;
  if (typeof window !== "undefined") {
    window.addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () {
        if (last && last.stats.total) renderColumns(last.nodes.hourly, last.stats, last.nodes.tip);
      }, 150);
    });
  }

  function render(stats, nodes) {
    last = { stats: stats, nodes: nodes };
    var empty = !stats.total, crit = (stats.series.CRITICAL || []).reduce(function (a, b) { return a + b; }, 0);
    nodes.note.textContent = empty ? "Không có sự cố nào trong " + (RANGE_TEXT[stats.range] || "khoảng này") + "."
      : "Tổng " + stats.total + " sự cố · " + crit + " CRITICAL · " + stats.rules.length + " nhóm luật" +
        (stats.truncated ? " · chỉ tính " + stats.limit + " sự cố mới nhất" : "");
    nodes.hourly.hidden = nodes.matrix.hidden = nodes.legend.hidden = empty;
    if (empty) return;
    renderLegend(nodes.legend, stats);
    renderColumns(nodes.hourly, stats, nodes.tip);
    renderMatrix(nodes.matrix, stats, nodes.tip);
    renderTable(nodes.table, stats);
  }

  var api = { render: render, bucket: bucket };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.IncidentCharts = api;
})(typeof window !== "undefined" ? window : this);
