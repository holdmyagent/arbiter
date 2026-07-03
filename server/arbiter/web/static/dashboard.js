// Theme toggle (mirrors the marketing site's data-theme mechanism)
const KEY = "hma-theme";
const root = document.documentElement;
const stored = localStorage.getItem(KEY);
if (stored === "light" || stored === "dark") root.dataset.theme = stored;
document.getElementById("theme-toggle")?.addEventListener("click", () => {
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem(KEY, root.dataset.theme);
});

// Live refresh: any request.* event reloads elements marked data-live (Task 9 pages use this)
function connect() {
  const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/v1/stream");
  ws.onmessage = (m) => {
    const evt = JSON.parse(m.data).event || "";
    if (!evt.startsWith("request.") && !evt.startsWith("device.")) return;
    document.querySelectorAll("[data-live]").forEach(async (el) => {
      const r = await fetch(el.dataset.live, {credentials: "same-origin"});
      if (r.redirected) { location.href = r.url; return; }
      if (r.ok) el.innerHTML = await r.text();
    });
  };
  ws.onclose = () => setTimeout(connect, 3000);
}
if (document.querySelector("[data-live]")) connect();

// TTL countdowns: <span class="countdown" data-expires="ISO8601">
setInterval(() => {
  document.querySelectorAll(".countdown[data-expires]").forEach((el) => {
    const left = (new Date(el.dataset.expires) - Date.now()) / 1000;
    el.textContent = left > 0
      ? `${Math.floor(left / 60)}:${String(Math.floor(left % 60)).padStart(2, "0")}`
      : "expired";
  });
}, 1000);
