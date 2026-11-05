// History: KSI coverage over time for the selected project.
(() => {
  const { el, formatDate, scans, selectScan, selectedScan } = Dash;
  const SVG = "http://www.w3.org/2000/svg";
  const PAD = { top: 16, right: 44, bottom: 26, left: 40 };

  function svg(tag, attrs, text) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const shortDate = (iso) =>
    new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });

  function draw(box, points) {
    // A hidden tab has no size but must still print; the observer redraws once it is shown
    const width = box.clientWidth || 720;
    const height = box.clientHeight || 260;

    const times = points.map((p) => new Date(p.generated_at).getTime());
    const first = times[0];
    const span = times[times.length - 1] - first || 1;
    const plotWidth = width - PAD.left - PAD.right;
    const plotHeight = height - PAD.top - PAD.bottom;
    const x = (time) => PAD.left + ((time - first) / span) * plotWidth;
    const y = (pct) => PAD.top + (1 - pct / 100) * plotHeight;
    const xs = times.map(x);

    const chart = svg("svg", {
      viewBox: `0 0 ${width} ${height}`,
      role: "img",
      "aria-label": "KSI coverage over time. The table below lists the same values.",
    });

    for (const tick of [0, 25, 50, 75, 100]) {
      chart.append(
        svg("line", { class: "grid-line", x1: PAD.left, x2: width - PAD.right, y1: y(tick), y2: y(tick) }),
        svg("text", { class: "axis-label", x: PAD.left - 8, y: y(tick) + 4, "text-anchor": "end" }, `${tick}%`));
    }

    const edges = [[0, "start"], [points.length - 1, "end"]];
    for (const [index, anchor] of edges) {
      chart.append(svg("text", {
        class: "axis-label", x: xs[index], y: height - 6, "text-anchor": anchor,
      }, shortDate(points[index].generated_at)));
    }

    chart.append(svg("polyline", {
      class: "line",
      points: points.map((p, i) => `${xs[i]},${y(p.coverage_pct)}`).join(" "),
    }));
    points.forEach((p, i) => {
      chart.append(svg("circle", { class: "point", cx: xs[i], cy: y(p.coverage_pct), r: 5 }));
    });

    const last = points[points.length - 1];
    chart.append(svg("text", {
      class: "value-label", x: xs[xs.length - 1] + 9, y: y(last.coverage_pct) + 4,
    }, `${last.coverage_pct}%`));

    const crosshair = svg("line", {
      class: "crosshair", y1: PAD.top, y2: height - PAD.bottom, visibility: "hidden",
    });
    chart.append(crosshair);

    const value = el("strong");
    const detail = el("span", { class: "muted" });
    const tooltip = el("div", { class: "tooltip", hidden: true }, value, detail);

    chart.addEventListener("pointermove", (event) => {
      const left = event.clientX - chart.getBoundingClientRect().left;
      let nearest = 0;
      xs.forEach((px, i) => {
        if (Math.abs(px - left) < Math.abs(xs[nearest] - left)) nearest = i;
      });
      const point = points[nearest];
      crosshair.setAttribute("x1", xs[nearest]);
      crosshair.setAttribute("x2", xs[nearest]);
      crosshair.setAttribute("visibility", "visible");
      value.textContent = `${point.coverage_pct}%`;
      detail.textContent = `${formatDate(point.generated_at)} · ${point.gap_count} gaps`;
      tooltip.hidden = false;
      const room = width - tooltip.offsetWidth - 4;
      tooltip.style.left = `${Math.max(0, Math.min(xs[nearest] + 10, room))}px`;
    });
    chart.addEventListener("pointerleave", () => {
      crosshair.setAttribute("visibility", "hidden");
      tooltip.hidden = true;
    });

    box.replaceChildren(chart, tooltip);
  }

  function trend(points) {
    const box = el("div", { class: "trend" });
    draw(box, points);
    new ResizeObserver(() => draw(box, points)).observe(box);
    return box;
  }

  function change(point, previous) {
    if (!previous) return "–";
    const delta = Math.round((point.coverage_pct - previous.coverage_pct) * 10) / 10;
    return `${delta > 0 ? "+" : ""}${delta}`;
  }

  function table(points) {
    const rows = points.map((point, i) => {
      const row = el("tr", null,
        el("td", { "data-date": formatDate(point.generated_at) },
          el("button", { type: "button", onclick: () => selectScan(i) },
            formatDate(point.generated_at))),
        el("td", null, `${point.coverage_pct}%`),
        el("td", null, change(point, points[i - 1])),
        el("td", null, String(point.gap_count)),
        el("td", null, String(point.gaps_by_severity.critical)));
      if (i === selectedScan()) row.setAttribute("aria-current", "true");
      return row;
    }).reverse();
    return el("div", { class: "table-scroll" },
      el("table", { class: "history-table" },
        el("thead", null, el("tr", null,
          ["Scan", "Coverage", "Change", "Gaps", "Critical"].map((h) => el("th", null, h)))),
        el("tbody", null, rows)));
  }

  Dash.view({
    id: "history",
    title: "History",
    render() {
      const points = scans();
      return el("div", null,
        el("div", { class: "panel" },
          el("h2", null, "KSI coverage over time"),
          points.length > 1
            ? trend(points)
            : el("div", { class: "empty" }, "Run another scan to see a trend.")),
        el("div", { class: "panel" }, el("h2", null, "Scans"), table(points)));
    },
  });
})();
