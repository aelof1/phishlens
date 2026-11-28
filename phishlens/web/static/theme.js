// Runs before first paint to avoid a flash of the wrong theme.
(function () {
  var root = document.documentElement;
  root.classList.add("js");
  try {
    var theme = localStorage.getItem("phishlens-theme");
    if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
  } catch (e) { /* storage blocked: follow the system theme */ }
})();
