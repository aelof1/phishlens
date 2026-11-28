// phishlens — progressive enhancement. Every page also works without JavaScript.
(function () {
  "use strict";
  var MAX = 2 * 1024 * 1024;
  var T = {};
  try { T = JSON.parse(document.getElementById("i18n").textContent); } catch (e) { /* keep defaults */ }
  function tr(key) { return T[key] || key; }

  // ---------- toasts ----------
  function toast(text, bad) {
    var box = document.querySelector(".toasts");
    if (!box) return;
    var el = document.createElement("div");
    el.className = "toast" + (bad ? " bad" : "");
    el.textContent = text;
    box.appendChild(el);
    setTimeout(function () { el.remove(); }, 3200);
  }

  // ---------- theme ----------
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.getAttribute("data-theme") ||
        (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("phishlens-theme", next); } catch (e) { /* ignore */ }
    });
  });

  // ---------- copy buttons ----------
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    var value = btn.getAttribute("data-copy");
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(function () { toast(tr("copied")); });
    } else {
      var ta = document.createElement("textarea");
      ta.value = value;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); toast(tr("copied")); } catch (e) { /* ignore */ }
      ta.remove();
    }
  });

  // ---------- confirmations and password checks ----------
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!confirm(tr("confirm_delete"))) ev.preventDefault();
    });
  });
  document.querySelectorAll("form[data-password-check]").forEach(function (form) {
    var pw = form.querySelector("[name=password]");
    var confirmInput = form.querySelector("[name=confirm]");
    if (!pw || !confirmInput) return;
    function check() { confirmInput.setCustomValidity(pw.value === confirmInput.value ? "" : " "); }
    pw.addEventListener("input", check);
    confirmInput.addEventListener("input", check);
  });

  // ---------- flash messages fade out ----------
  document.querySelectorAll(".content > .flash-ok").forEach(function (el) {
    setTimeout(function () { el.style.transition = "opacity .4s"; el.style.opacity = "0"; }, 4000);
    setTimeout(function () { el.remove(); }, 4500);
  });
  if (/[?&](ok|err)=/.test(location.search) && history.replaceState) {
    history.replaceState(null, "", location.pathname);
  }

  // ---------- animated numbers ----------
  function countUp(root) {
    root.querySelectorAll("[data-count]").forEach(function (el) {
      var target = parseInt(el.getAttribute("data-count"), 10) || 0;
      if (matchMedia("(prefers-reduced-motion: reduce)").matches || target === 0) return;
      var start = null;
      function step(ts) {
        if (start === null) start = ts;
        var p = Math.min(1, (ts - start) / 900);
        el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
        if (p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }
  countUp(document);

  // ---------- analyze form ----------
  var form = document.getElementById("analyze-form");
  if (!form) return;
  var zone = form.querySelector("[data-dropzone]");
  var input = form.querySelector("input[type=file]");
  var title = form.querySelector("[data-drop-title]");
  var source = form.querySelector("textarea[name=source]");
  var submit = form.querySelector("[data-submit]");
  var result = document.getElementById("result");
  var defaultTitle = title.textContent;

  function showFile() {
    var file = input.files && input.files[0];
    zone.classList.toggle("has-file", !!file);
    title.textContent = file ? file.name + " · " + Math.ceil(file.size / 1024) + " KB" : defaultTitle;
    if (file && file.size > MAX) toast(tr("file_too_big"), true);
  }
  input.addEventListener("change", showFile);
  ["dragenter", "dragover"].forEach(function (name) {
    zone.addEventListener(name, function (ev) { ev.preventDefault(); zone.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (name) {
    zone.addEventListener(name, function (ev) { ev.preventDefault(); zone.classList.remove("drag"); });
  });
  zone.addEventListener("drop", function (ev) {
    if (ev.dataTransfer && ev.dataTransfer.files.length) {
      input.files = ev.dataTransfer.files;
      showFile();
    }
  });
  // Dropping anywhere else on the page must not open the email in the browser
  window.addEventListener("dragover", function (ev) { ev.preventDefault(); });
  window.addEventListener("drop", function (ev) { ev.preventDefault(); });
  form.addEventListener("reset", function () {
    setTimeout(showFile, 0);
    result.textContent = "";
  });

  function busy(on) {
    submit.disabled = on;
    submit.innerHTML = "";
    if (on) {
      var s = document.createElement("span");
      s.className = "spinner";
      submit.appendChild(s);
    }
    var label = document.createElement("span");
    label.textContent = on ? tr("analyzing") : tr("analyze_btn");
    submit.appendChild(label);
  }

  form.addEventListener("submit", function (ev) {
    var file = input.files && input.files[0];
    if (!file && !source.value.trim()) {
      ev.preventDefault();
      toast(tr("empty_input"), true);
      return;
    }
    if (file && file.size > MAX) {
      ev.preventDefault();
      toast(tr("file_too_big"), true);
      return;
    }
    if (!window.fetch || !window.FormData) return; // plain form post
    ev.preventDefault();
    busy(true);
    fetch(form.action, {
      method: "POST", body: new FormData(form), credentials: "same-origin",
      headers: { "X-Partial": "1" }
    }).then(function (resp) {
      if (resp.redirected || resp.status === 401) { location.reload(); return null; }
      return resp.text();
    }).then(function (html) {
      if (html === null) return;
      // Server-rendered fragment: every email value is HTML-escaped on the server
      result.innerHTML = html;
      countUp(result);
      result.scrollIntoView({ behavior: "smooth", block: "start" });
    }).catch(function () {
      toast(tr("network_error"), true);
    }).then(function () { busy(false); });
  });
})();
