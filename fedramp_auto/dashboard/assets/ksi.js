// KSIs: every indicator in the baseline, drilling down to the evidence behind it.
(() => {
  const { el, severity } = Dash;
  const RANK = { critical: 0, high: 1, medium: 2, low: 3 };
  const filters = { status: "all", search: "" };

  function matches(ksi) {
    if (filters.status === "gaps" && ksi.satisfied) return false;
    if (filters.status === "satisfied" && !ksi.satisfied) return false;
    const needle = filters.search.trim().toLowerCase();
    if (!needle) return true;
    const haystack = [ksi.ksi_id, ksi.title, ...ksi.controls.map((c) => c.id)].join(" ");
    return haystack.toLowerCase().includes(needle);
  }

  const evidence = (resource) =>
    el("li", null,
      el("code", null, resource.identifier), " ",
      el("span", { class: "muted" }, `in ${resource.file}`),
      el("div", null, resource.rationale));

  const control = ({ id, resources }) =>
    el("div", { class: "control" },
      el("h3", null, id),
      resources.length
        ? el("ul", null, resources.map(evidence))
        : el("div", { class: "muted" }, "No resource provides this control."));

  const row = (ksi) => {
    const met = ksi.controls.filter((c) => c.resources.length).length;
    return el("details", { class: "ksi" },
      el("summary", null,
        el("span", { class: "ksi-id" }, ksi.ksi_id),
        el("span", { class: "ksi-title" }, ksi.title),
        severity(ksi.severity),
        el("span", { class: ksi.satisfied ? "status-ok" : "status-gap" },
          ksi.satisfied ? "Satisfied" : "Gap"),
        el("span", { class: "ksi-count muted" }, `${met} of ${ksi.controls.length}`)),
      el("div", { class: "ksi-detail" },
        ksi.description ? el("p", null, ksi.description) : null,
        ksi.controls.map(control)));
  };

  function list(scan) {
    const rows = scan.ksis.filter(matches).sort((a, b) =>
      a.satisfied - b.satisfied ||
      RANK[a.severity] - RANK[b.severity] ||
      a.ksi_id.localeCompare(b.ksi_id));
    return rows.length
      ? rows.map(row)
      : [el("div", { class: "empty" }, "No KSIs match these filters.")];
  }

  Dash.view({
    id: "ksi",
    title: "KSIs",
    render(scan) {
      const results = el("div", null, list(scan));
      const refresh = () => results.replaceChildren(...list(scan));
      const status = el("select", {
        ariaLabel: "Filter by status",
        onchange: (e) => { filters.status = e.target.value; refresh(); },
      },
        el("option", { value: "all" }, "All KSIs"),
        el("option", { value: "gaps" }, "Gaps only"),
        el("option", { value: "satisfied" }, "Satisfied only"));
      status.value = filters.status;

      return el("div", { class: "panel" },
        el("div", { class: "filters" },
          status,
          el("input", {
            type: "search",
            placeholder: "Search by KSI, title or control",
            ariaLabel: "Search KSIs",
            value: filters.search,
            oninput: (e) => { filters.search = e.target.value; refresh(); },
          })),
        el("div", { class: "ksi-head" },
          el("span", null, "KSI"), el("span", null, "Title"), el("span", null, "Severity"),
          el("span", null, "Status"), el("span", null, "Controls")),
        results);
    },
  });
})();
