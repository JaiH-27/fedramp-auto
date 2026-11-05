// Overview: the headline numbers for the selected scan.
(() => {
  const { el, severity, formatDate } = Dash;
  const CLOUDS = { aws: "AWS (Terraform)", azure: "Azure (Terraform)", cdk: "AWS (CDK)" };

  const tile = (label, value, note) =>
    el("div", { class: "tile" },
      el("div", { class: "label" }, label),
      el("div", { class: "value" }, String(value)),
      note ? el("div", { class: "note" }, note) : null);

  function coverageChange(scan, previous) {
    if (!previous) return null;
    const change = Math.round((scan.coverage_pct - previous.coverage_pct) * 10) / 10;
    if (change === 0) return "No change since the previous scan";
    return `${change > 0 ? "+" : ""}${change} points since the previous scan`;
  }

  function severityBars(counts) {
    const largest = Math.max(1, ...Object.values(counts));
    return el("div", { class: "severity-bars" },
      Object.entries(counts).flatMap(([name, count]) => [
        severity(name),
        el("div", { class: `track sev-${name}` },
          el("div", { class: "bar", style: `width:${(count / largest) * 100}%` })),
        el("span", { class: "count" }, String(count)),
      ]));
  }

  Dash.view({
    id: "overview",
    title: "Overview",
    render(scan, previous) {
      return el("div", null,
        el("p", { class: "scan-meta" },
          `${scan.target} · ${scan.baseline.toUpperCase()} baseline · ` +
          `${CLOUDS[scan.cloud] || scan.cloud} · scanned ${formatDate(scan.generated_at)}`),
        el("div", { class: "tiles" },
          tile("KSI coverage", `${scan.coverage_pct}%`, coverageChange(scan, previous)),
          tile("KSIs satisfied", `${scan.satisfied_ksi_count} of ${scan.total_ksi_count}`),
          tile("Open gaps", scan.gap_count),
          tile("Critical gaps", scan.gaps_by_severity.critical),
          tile("Resources scanned", scan.resource_count)),
        el("div", { class: "panel" },
          el("h2", null, "Open gaps by severity"),
          severityBars(scan.gaps_by_severity)));
    },
  });
})();
