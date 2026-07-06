// Theme + typeface (persisted via localStorage; CSS defaults dark, honors
// the OS light preference when no explicit choice has been stamped).
const THEME_KEY = "hma-theme";
const FACE_KEY = "hma-face";
const root = document.documentElement;

const storedTheme = localStorage.getItem(THEME_KEY);
if (storedTheme === "light" || storedTheme === "dark") root.dataset.theme = storedTheme;
const storedFace = localStorage.getItem(FACE_KEY);
if (storedFace === "mono" || storedFace === "sans") root.dataset.face = storedFace;

function effectiveTheme() {
  if (root.dataset.theme === "light" || root.dataset.theme === "dark") return root.dataset.theme;
  return matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function effectiveFace() {
  return root.dataset.face === "sans" ? "sans" : "mono";
}

function syncChrome() {
  const themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) themeBtn.textContent = effectiveTheme() === "dark" ? "◐ Dark" : "◑ Light";
  document.querySelectorAll("[data-set-theme]").forEach((b) => {
    b.classList.toggle("on", b.dataset.setTheme === effectiveTheme());
  });
  document.querySelectorAll("[data-set-face]").forEach((b) => {
    b.classList.toggle("on", b.dataset.setFace === effectiveFace());
  });
}

function setTheme(mode) {
  root.dataset.theme = mode;
  localStorage.setItem(THEME_KEY, mode);
  syncChrome();
}

function setFace(face) {
  root.dataset.face = face;
  localStorage.setItem(FACE_KEY, face);
  syncChrome();
}

document.getElementById("theme-toggle")?.addEventListener("click", () => {
  setTheme(effectiveTheme() === "dark" ? "light" : "dark");
});
document.getElementById("face-toggle")?.addEventListener("click", () => {
  setFace(effectiveFace() === "mono" ? "sans" : "mono");
});

// Copy-to-clipboard: async Clipboard API when available (insecure-context /
// http://LAN-IP has none), else a hidden-textarea execCommand fallback. The
// button only claims success when a method actually reported one.
const copyRevertTimers = new WeakMap();

function legacyCopy(txt) {
  const ta = document.createElement("textarea");
  ta.value = txt;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  ta.style.left = "-1000px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}

async function copyToButton(btn) {
  btn.dataset.label ||= btn.textContent;
  const txt = btn.getAttribute("data-copy") || "";
  let ok = false;
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(txt);
      ok = true;
    } catch {
      ok = legacyCopy(txt);
    }
  } else {
    ok = legacyCopy(txt);
  }
  clearTimeout(copyRevertTimers.get(btn));
  btn.textContent = ok ? "Copied" : "Failed";
  btn.classList.toggle("done", ok);
  copyRevertTimers.set(btn, setTimeout(() => {
    btn.textContent = btn.dataset.label;
    btn.classList.remove("done");
  }, 1200));
}

// Delegated handlers: Settings segmented controls + copy buttons.
document.addEventListener("click", (e) => {
  const themeSeg = e.target.closest("[data-set-theme]");
  if (themeSeg) { setTheme(themeSeg.dataset.setTheme); return; }
  const faceSeg = e.target.closest("[data-set-face]");
  if (faceSeg) { setFace(faceSeg.dataset.setFace); return; }
  const copyBtn = e.target.closest(".copy-btn[data-copy]");
  if (copyBtn) { copyToButton(copyBtn); return; }
});

syncChrome();

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
      const count = document.querySelector(".eyebrow .count");
      if (count && el.dataset.live.startsWith("/dashboard/requests")) {
        const pending = el.querySelectorAll(".approval").length;
        const decided = el.querySelectorAll(".lrow.r4:not(.lhead)").length;
        count.textContent = `${pending} waiting · ${pending + decided} total`;
      }
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
    const warn = left > 0 && left < 60;
    el.classList.toggle("warn", warn);
    el.closest(".expiry")?.classList.toggle("warn", warn);
  });
}, 1000);
