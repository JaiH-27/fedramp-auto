// Shell of the dashboard: state, tabs and the helpers every view uses.
// Scan data comes from user files, so it only ever reaches the DOM as text.
const Dash = (() => {
  const data = JSON.parse(document.getElementById("scan-data").textContent);
  const views = [];
  const state = { group: data.groups.length - 1, scan: null, view: null };

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (key in node) node[key] = value;
      else node.setAttribute(key, value);
    }
    node.append(...children.flat().filter((c) => c !== null && c !== undefined));
    return node;
  }

  const severity = (name) => el("span", { class: `badge sev-${name}` }, name);

  const formatDate = (iso) =>
    new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

  const group = () => data.groups[state.group];
  const scans = () => group().scans;

  function fillSelect(select, labels, selected) {
    select.replaceChildren(
      ...labels.map((label, i) => el("option", { value: String(i), selected: i === selected }, label))
    );
  }

  function showView(id) {
    state.view = id;
    for (const view of views) {
      document.getElementById(`view-${view.id}`).hidden = view.id !== id;
      const tab = document.getElementById(`tab-${view.id}`);
      if (view.id === id) tab.setAttribute("aria-current", "page");
      else tab.removeAttribute("aria-current");
    }
  }

  function render() {
    const groupSelect = document.getElementById("group");
    const scanSelect = document.getElementById("scan");
    fillSelect(groupSelect, data.groups.map((g) => g.key), state.group);
    fillSelect(scanSelect, scans().map((s) => formatDate(s.generated_at)), state.scan);
    const scan = scans()[state.scan];
    const previous = scans()[state.scan - 1] || null;
    for (const view of views) {
      document.getElementById(`view-${view.id}`).replaceChildren(view.render(scan, previous));
    }
  }

  function selectGroup(index) {
    state.group = index;
    state.scan = scans().length - 1;
    render();
  }

  function selectScan(index) {
    state.scan = index;
    render();
  }

  function start() {
    const tabs = document.getElementById("tabs");
    const main = document.getElementById("views");
    for (const view of views) {
      tabs.append(el("button", { id: `tab-${view.id}`, onclick: () => showView(view.id) }, view.title));
      main.append(el("section", {
        id: `view-${view.id}`, class: "view", hidden: true, "data-title": view.title,
      }));
    }
    document.getElementById("group").addEventListener("change", (e) => selectGroup(+e.target.value));
    document.getElementById("scan").addEventListener("change", (e) => selectScan(+e.target.value));
    selectGroup(state.group);
    showView(views[0].id);
  }

  return {
    el, severity, formatDate, scans, selectScan, start,
    selectedScan: () => state.scan,
    view: (definition) => views.push(definition),
  };
})();
