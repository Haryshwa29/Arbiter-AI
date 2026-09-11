// Synchronous before first paint; served locally to satisfy the script CSP.
(function () {
  try {
    var v = localStorage.getItem("arbiter-theme");
    if (v !== "light" && v !== "dark") {
      v = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.setAttribute("data-theme", v);
  } catch {}
})();
