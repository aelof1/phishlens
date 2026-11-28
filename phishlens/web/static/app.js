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

  // ---------- AI settings: fill URL and model from the chosen preset ----------
  var provider = document.querySelector("[data-provider]");
  if (provider) {
    var urlInput = document.querySelector("[data-url]");
    var modelInput = document.querySelector("[data-model]");
    var warning = document.querySelector("[data-cloud-warning]");
    var previous = provider.options[provider.selectedIndex];
    provider.addEventListener("change", function () {
      var opt = provider.options[provider.selectedIndex];
      // Replace the fields only if they still hold the previous preset's values
      if (!urlInput.value || urlInput.value === previous.getAttribute("data-url")) {
        urlInput.value = opt.getAttribute("data-url");
      }
      if (!modelInput.value || modelInput.value === previous.getAttribute("data-model")) {
        modelInput.value = opt.getAttribute("data-model");
      }
      warning.hidden = opt.getAttribute("data-cloud") !== "1";
      previous = opt;
    });
  }

  // ---------- country names in the interface language ----------
  var regionNames = null;
  try { regionNames = new Intl.DisplayNames([document.documentElement.lang || "en"], { type: "region" }); }
  catch (e) { /* old browser: keep the codes */ }
  function countryName(code) {
    try { return (regionNames && regionNames.of(code)) || code; } catch (e) { return code; }
  }
  function localize(root) {
    root.querySelectorAll("[data-cc]:not(path)").forEach(function (el) {
      var code = el.getAttribute("data-cc");
      el.textContent = countryName(code);
      el.title = code;
    });
  }
  localize(document);

  // ---------- busy buttons (slow server actions) ----------
  document.querySelectorAll("form[data-busy]").forEach(function (f) {
    f.addEventListener("submit", function () {
      var b = f.querySelector("button");
      if (b) { b.disabled = true; b.insertBefore(document.createElement("span"), b.firstChild).className = "spinner"; }
    });
  });

  // ---------- dashboard: map + live refresh ----------
  var live = document.getElementById("dash-live");
  if (live) {
    var mapBox = document.querySelector("[data-map]");
    var tip = document.querySelector("[data-map-tip]");
    var liveText = document.querySelector("[data-live-text]");
    var liveDot = document.querySelector("[data-live]");
    var mode = "total";
    var data = readData();
    var cssLink = document.querySelector('link[rel="stylesheet"]');
    var version = cssLink ? (cssLink.href.split("v=")[1] || "") : "";

    function readData() {
      try { return JSON.parse(document.getElementById("dash-data").textContent); }
      catch (e) { return { countries: [], last: 0 }; }
    }

    function colorMap() {
      if (!mapBox.querySelector("svg")) return;
      var counts = {};
      var max = 0;
      data.countries.forEach(function (c) {
        counts[c.country] = c;
        max = Math.max(max, c[mode]);
      });
      mapBox.querySelectorAll("path[data-cc]").forEach(function (p) {
        var c = counts[p.getAttribute("data-cc")];
        var n = c ? c[mode] : 0;
        var level = n > 0 && max > 0 ? Math.max(1, Math.ceil(5 * Math.log(1 + n) / Math.log(1 + max))) : 0;
        p.setAttribute("data-level", String(level));
      });
    }

    function showTip(ev, path) {
      var code = path.getAttribute("data-cc");
      if (!code) { tip.hidden = true; return; }
      var c = data.countries.filter(function (x) { return x.country === code; })[0] || { total: 0, phishing: 0 };
      tip.textContent = tr("map_tip").replace("{name}", countryName(code))
        .replace("{total}", c.total).replace("{phishing}", c.phishing);
      var box = mapBox.getBoundingClientRect();
      var card = mapBox.parentNode.getBoundingClientRect();
      tip.style.left = Math.min(ev.clientX - card.left + 12, box.width - 180) + "px";
      tip.style.top = (ev.clientY - card.top + 12) + "px";
      tip.hidden = false;
    }

    if (mapBox && window.fetch) {
      fetch("/static/world.svg?v=" + version).then(function (r) { return r.text(); }).then(function (svg) {
        mapBox.innerHTML = svg; // our own static file, not user data
        mapBox.querySelectorAll("title").forEach(function (t) { t.remove(); });
        colorMap();
        mapBox.addEventListener("mousemove", function (ev) {
          if (ev.target.tagName === "path") showTip(ev, ev.target); else tip.hidden = true;
        });
        mapBox.addEventListener("click", function (ev) {
          if (ev.target.tagName === "path") showTip(ev, ev.target);
        });
        mapBox.addEventListener("mouseleave", function () { tip.hidden = true; });
      });
    }
    document.querySelectorAll("[data-map-mode]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        mode = btn.getAttribute("data-map-mode");
        mapBox.parentNode.setAttribute("data-mode", mode);
        document.querySelectorAll("[data-map-mode]").forEach(function (b) { b.classList.toggle("active", b === btn); });
        colorMap();
      });
    });

    function animateFrom(oldValues) {
      live.querySelectorAll("[data-count]").forEach(function (el, i) {
        var from = oldValues[i] || 0;
        var to = parseInt(el.getAttribute("data-count"), 10) || 0;
        if (from === to) return;
        el.classList.add("bump");
        var start = null;
        function step(ts) {
          if (start === null) start = ts;
          var p = Math.min(1, (ts - start) / 700);
          el.textContent = Math.round(from + (to - from) * p);
          if (p < 1) requestAnimationFrame(step); else el.classList.remove("bump");
        }
        requestAnimationFrame(step);
      });
    }

    function setStatus(text, paused) {
      if (liveText) liveText.textContent = text;
      if (liveDot) liveDot.classList.toggle("paused", !!paused);
    }

    function tick() {
      if (document.hidden) { setStatus(tr("live_paused"), true); return; }
      fetch("/api/stats", { credentials: "same-origin" }).then(function (r) {
        if (r.status === 401) { location.reload(); return null; }
        return r.ok ? r.json() : null;
      }).then(function (stats) {
        if (!stats) return;
        setStatus(tr("live_updated").replace("{time}", new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })));
        if (stats.last_event === data.last) return;
        var oldValues = Array.prototype.map.call(live.querySelectorAll("[data-count]"), function (el) {
          return parseInt(el.getAttribute("data-count"), 10) || 0;
        });
        return fetch(live.getAttribute("data-refresh"), { credentials: "same-origin" })
          .then(function (r) { return r.ok ? r.text() : null; })
          .then(function (html) {
            if (html === null) return;
            live.innerHTML = html; // server-rendered fragment, every value escaped on the server
            data = readData();
            localize(live);
            colorMap();
            animateFrom(oldValues);
          });
      }).catch(function () { setStatus(tr("network_error"), true); });
    }
    setInterval(tick, 10000);
    document.addEventListener("visibilitychange", function () { if (!document.hidden) tick(); });
  }

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
