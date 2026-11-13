// Posts the secret once and keeps the session the answer holds in this
// tab's sessionStorage; the page then sends it as a header with every API
// call. The secret never appears in a URL, and nothing is kept in a cookie.
"use strict";
(function () {
  var form = document.querySelector(".login-form");
  if (!form) return;
  var button = form.querySelector(".login-submit");
  var input = form.querySelector(".login-input");
  var error = document.getElementById("login-error");
  var label = button.textContent;
  // The token can be shown, to check what was pasted, and hidden again.
  var reveal = form.querySelector(".reveal");
  if (reveal) {
    reveal.addEventListener("click", function () {
      var shown = input.type === "password";
      input.type = shown ? "text" : "password";
      var say = shown ? "Hide" : "Show";
      reveal.setAttribute("aria-label", say);
      reveal.title = say;
      reveal.setAttribute("aria-pressed", String(shown));
      reveal.querySelector(".reveal-show").hidden = shown;
      reveal.querySelector(".reveal-hide").hidden = !shown;
      input.focus();
    });
  }
  function show(text) {
    error.textContent = text;
    error.hidden = !text;
    if (text) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
  }
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    button.disabled = true;
    button.textContent = "Checking…";
    show("");
    fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: input.value }),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (v) { return { ok: r.ok, v: v }; });
    }).then(function (a) {
      if (a.ok && a.v.session) {
        try { sessionStorage.setItem("nerve.session", a.v.session); } catch (_) { /* blocked: the page asks again */ }
        location.replace("/");
        return;
      }
      show(a.v.error || "Cannot sign in.");
      button.disabled = false;
      button.textContent = label;
      input.select();
    }, function () {
      show("Cannot reach the server. Try again.");
      button.disabled = false;
      button.textContent = label;
    });
  });
  window.addEventListener("pageshow", function () {
    button.disabled = false;
    button.textContent = label;
  });
})();
