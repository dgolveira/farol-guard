(function () {
  var t = null;
  try { t = localStorage.getItem("farol.theme"); } catch (e) { t = null; }
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
})();
