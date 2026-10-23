(function () {
  var t = null;
  try { t = localStorage.getItem("farol.theme"); } catch (e) { t = null; }
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);

  var buf = new Uint8Array(12);
  (window.crypto || window.msCrypto).getRandomValues(buf);
  var id = Array.prototype.map.call(buf, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  function ping() {
    fetch("/api/ping?page=" + id, { credentials: "same-origin", cache: "no-store" }).catch(function () {});
  }
  ping();
  setInterval(ping, 10000);
  window.addEventListener("pagehide", function () {
    try {
      fetch("/api/bye?page=" + id, { method: "POST", keepalive: true, credentials: "same-origin", headers: { "X-Farol-Request": "1" } });
    } catch (e) { /* page is closing */ }
  });
  document.addEventListener("visibilitychange", function () { if (!document.hidden) ping(); });
})();
