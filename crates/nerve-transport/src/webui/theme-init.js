// Runs in the head, before the first paint, so the page never flashes the
// wrong theme. "system" (the default) follows the browser; the choice is
// kept in localStorage by the theme buttons in app.js.
(function () {
  var t = "system";
  try {
    t = localStorage.getItem("nerve.theme") || "system";
  } catch (_) { /* storage blocked: follow the system */ }
  var dark = t === "dark" || (t !== "light" && !matchMedia("(prefers-color-scheme: light)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  var m = document.querySelector('meta[name="theme-color"]');
  if (m) m.content = dark ? "#0f1116" : "#f4f5f9";
})();
