// Printing: a report needs the detail that the screen keeps folded away.
(() => {
  let opened = [];

  window.addEventListener("beforeprint", () => {
    opened = [...document.querySelectorAll("details:not([open])")];
    opened.forEach((details) => { details.open = true; });
  });

  window.addEventListener("afterprint", () => {
    opened.forEach((details) => { details.open = false; });
    opened = [];
  });

  document.querySelector(".controls").append(
    Dash.el("button", { type: "button", onclick: () => window.print() }, "Print report"));
})();
