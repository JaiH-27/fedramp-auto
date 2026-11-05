// Remediation: what to fix for each open gap, most severe first.
(() => {
  const { el, severity } = Dash;
  const LANGUAGES = { hcl: "Terraform", typescript: "AWS CDK" };

  function copyButton(text) {
    if (!navigator.clipboard) return null;  // file:// pages are not a secure context
    const button = el("button", {
      type: "button",
      onclick: async () => {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = "Copy"; }, 1500);
      },
    }, "Copy");
    return button;
  }

  const fix = (item) =>
    el("article", { class: "panel fix" },
      el("h2", null,
        el("span", { class: "ksi-id" }, item.ksi_id),
        el("span", null, item.title),
        severity(item.severity)),
      el("p", { class: "muted" }, item.risk),
      el("p", null, item.action),
      el("details", null,
        el("summary", null, `${LANGUAGES[item.language] || item.language} snippet`),
        el("div", { class: "snippet-bar" }, el("span"), copyButton(item.snippet)),
        el("pre", null, el("code", null, item.snippet))));

  Dash.view({
    id: "remediation",
    title: "Remediation",
    render(scan) {
      if (!scan.remediations.length) {
        return el("div", { class: "panel empty" }, "No remediation needed: this scan has no open gaps.");
      }
      return el("div", null, scan.remediations.map(fix));
    },
  });
})();
