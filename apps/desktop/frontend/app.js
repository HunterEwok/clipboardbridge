// SPDX-License-Identifier: AGPL-3.0-only
// The tray app's window: the group's devices as tiles, a list or orbits
// around this computer, a device's details beside them, send and fetch
// (docs/apps.md, "The tray app"). It asks the Go side (desk.go) for the
// state every few seconds; every action goes through the Go side too.

import { Call } from "/wails/runtime.js";
import { colors, radius, spacing } from "./tokens.js";

const call = (method, ...args) => Call.ByName("main.Desk." + method, ...args);
const $ = (id) => document.getElementById(id);

let state = null;
let selected = null;
let tr = {};
let lang = "";

// t translates an English text; %s and %d take the arguments in order.
function t(s, ...args) {
  let out = tr[s] ?? s;
  for (const a of args) out = out.replace(/%[sd]/, String(a));
  return out;
}

async function loadLanguage(l) {
  if (l === lang) return;
  lang = l;
  tr = {};
  if (l !== "en") {
    try {
      tr = await (await fetch(`l10n/${l}.json`)).json();
    } catch (e) {
      console.error("l10n", e);
    }
  }
  document.documentElement.lang = l;
  for (const el of document.querySelectorAll("[data-t]")) {
    el.dataset.en ??= el.textContent;
    el.textContent = t(el.dataset.en);
  }
  for (const el of document.querySelectorAll("[data-t-title]")) {
    el.title = t(el.dataset.tTitle);
    el.setAttribute("aria-label", el.title);
  }
}

// The colours: the chosen accent on the dark or light base, as the phones.
const darkQuery = matchMedia("(prefers-color-scheme: dark)");

function applyTheme() {
  const s = state?.settings ?? {};
  const pair = colors.find((c) => c.name === s.color) ?? colors[0];
  const dark = s.appearance === "dark" || (s.appearance !== "light" && darkQuery.matches);
  const p = dark ? pair.dark : pair.light;
  const root = document.documentElement.style;
  const alpha = (hex, a) => hex + Math.round(a * 255).toString(16).padStart(2, "0");
  root.setProperty("--background", p.background);
  root.setProperty("--surface", p.surface);
  root.setProperty("--text", p.text);
  root.setProperty("--text-dim", p.textDim);
  root.setProperty("--accent", p.accent);
  root.setProperty("--on-accent", p.onAccent);
  root.setProperty("--danger", p.danger);
  root.setProperty("--glass", dark ? alpha(p.surface, 0.78) : "#FFFFFFDB");
  root.setProperty("--soft", alpha(p.accent, dark ? 0.16 : 0.1));
  root.setProperty("--line", alpha(p.text, dark ? 0.12 : 0.1));
  root.setProperty("color-scheme", dark ? "dark" : "light");
  for (const [k, v] of Object.entries(radius)) root.setProperty(`--radius-${k}`, v + "px");
  for (const [k, v] of Object.entries(spacing)) root.setProperty(`--spacing-${k}`, v + "px");
}
darkQuery.addEventListener("change", applyTheme);

// What a device is: its form from its hello, else its role and system.
const kinds = {
  laptop: "Laptop", desktop: "Computer", phone: "Phone", tablet: "Tablet", tv: "TV", board: "Board",
  server: "Server", router: "Router", console: "Game console", watch: "Watch", retro: "Retro computer", other: "Device",
};

export function kindOf(d) {
  if (d.form && kinds[d.form]) return d.form;
  if (d.role === "phone" || d.role === "shortcut") return "phone";
  if (d.role === "lite") return "board";
  if (d.role === "watch") return "watch";
  if (d.os === "macos") return "laptop";
  if (d.os === "ios" || d.os === "android") return "phone";
  return "desktop";
}

const systems = {
  linux: "Linux", windows: "Windows", macos: "macOS", ios: "iOS", android: "Android", watchos: "watchOS", wearos: "Wear OS",
};

export function systemWithVersion(d) {
  const s = systems[d.os];
  if (!s) return d.os_version ?? "";
  if (!d.os_version) return s;
  return d.os === "linux" ? d.os_version : `${s} ${d.os_version}`;
}

// The kinds' outlines on a grid of 24, as the Android app draws them.
const shapes = {
  laptop: '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
  desktop: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M12 16v4M8 20h8"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>',
  tablet: '<rect x="4.5" y="2.5" width="15" height="19" rx="2"/><path d="M10.5 18.5h3"/>',
  tv: '<rect x="2.5" y="5" width="19" height="12" rx="1.5"/><path d="M8 20.5h8M9 2l3 3 3-3"/>',
  board: '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5" rx=".8"/>' +
    '<path d="M9 2.5V6M12 2.5V6M15 2.5V6M9 18v3.5M12 18v3.5M15 18v3.5M2.5 9H6M2.5 12H6M2.5 15H6M18 9h3.5M18 12h3.5M18 15h3.5"/>',
  server: '<rect x="4" y="3.5" width="16" height="7" rx="1.5"/><rect x="4" y="13.5" width="16" height="7" rx="1.5"/>' +
    '<circle cx="8" cy="7" r="1" fill="currentColor"/><circle cx="8" cy="17" r="1" fill="currentColor"/>',
  router: '<rect x="3" y="12" width="18" height="8" rx="1.5"/><path d="M7 12L5 4M17 12l2-8"/>' +
    '<circle cx="7.5" cy="16" r="1" fill="currentColor"/><circle cx="11" cy="16" r="1" fill="currentColor"/>',
  console: '<rect x="2.5" y="7" width="19" height="11" rx="5"/><path d="M7 10.5v4M5 12.5h4"/>' +
    '<circle cx="15.5" cy="11" r="1" fill="currentColor"/><circle cx="17.5" cy="13.5" r="1" fill="currentColor"/>',
  watch: '<rect x="7" y="6" width="10" height="12" rx="3"/><path d="M9 6l.5-3.5M15 6l-.5-3.5M9 18l.5 3.5M15 18l-.5 3.5"/>',
  retro: '<rect x="2" y="7" width="20" height="10" rx="1.5"/><path d="M7 14h10"/>' +
    [6, 9, 12, 15, 18].map((x) => `<circle cx="${x}" cy="10.5" r=".8" fill="currentColor"/>`).join(""),
  other: '<rect x="4" y="7" width="16" height="13" rx="1.5"/><path d="M4 11h16M9 3.5L4 7M15 3.5l5 3.5M9 3.5h6"/>',
};

function glyph(d, size = 44) {
  const on = d.online || d.self;
  return `<span class="glyph${on ? " on" : ""}" style="width:${size}px;height:${size}px" aria-hidden="true">` +
    `<svg width="${size * 0.56}" height="${size * 0.56}" viewBox="0 0 24 24" fill="none" stroke="currentColor" ` +
    `stroke-width="1.8" stroke-linecap="round">${shapes[kindOf(d)]}</svg></span>`;
}

// The sync modes (docs/design.md, "Sync modes"), in the order they show.
const modes = ["own", "shared", "receive", "send"];
const modeName = (m) => ({ own: t("Own clipboard"), shared: t("Shared"), receive: t("Receive only"), send: t("Send only") })[m] ?? m;

// modeButtons is a row of the four modes; id names the device, "" this
// computer.
function modeButtons(current, id) {
  return modes.map((m) => `<button type="button" data-mode="${m}" data-mode-for="${esc(id)}" aria-checked="${m === current}" ` +
    `${state.busy ? "disabled" : ""}>${esc(modeName(m))}</button>`).join("");
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const dot = (on) => `<span class="dot${on ? " on" : ""}"></span>`;

// render draws the whole window from the state.
function render() {
  const s = state;
  const others = s.devices.filter((d) => !d.self);
  const inGroup = !s.problem && s.status && s.status.group && !s.status.removed;
  const online = others.filter((d) => d.online).length;
  $("headline").textContent = s.problem ? t("The service does not answer")
    : !inGroup ? t("This computer is in no group yet") : t("%d of %d online", online, others.length);
  $("tag").textContent = inGroup ? s.status.group : "";
  renderAway(inGroup ? s.status.away : undefined, inGroup);
  for (const b of document.querySelectorAll("[data-layout]")) b.setAttribute("aria-checked", String(b.dataset.layout === s.settings.layout));
  $("bar").hidden = !inGroup;
  $("send").disabled = $("fetch").disabled = s.busy;
  $("message").textContent = s.message ?? "";

  // The details first: the orbits fit the room they leave.
  renderDetail();
  const box = $("devices");
  box.classList.toggle("fixed", inGroup && others.length > 0 && s.settings.layout === "orbit");
  if (s.problem) {
    box.innerHTML = `<div class="notice"><div class="big">⚠</div><h2>${esc(t("The service does not answer"))}</h2><p class="dim">${esc(s.problem)}</p></div>`;
  } else if (!inGroup) {
    box.innerHTML = `<div class="notice"><div class="big">⧉</div><h2>${esc(t("This computer is in no group yet"))}</h2>` +
      `<p class="dim">${esc(t("Run cbb pair in a terminal and scan its QR code with the phone app, or make a group of computers with cbb new."))}</p></div>`;
  } else if (others.length === 0) {
    box.innerHTML = `<div class="notice"><div class="big">＋</div><h2>${esc(t("No other devices yet"))}</h2><p class="dim">${esc(t("Add one with the + button."))}</p></div>`;
  } else if (s.settings.layout === "list") {
    box.innerHTML = `<div class="list">${others.map((d) =>
      `<button class="row${d.id === selected ? " selected" : ""}" data-id="${esc(d.id)}">${glyph(d, 32)}` +
      `<span class="name">${esc(d.name)}</span><span class="dim">${esc(systemWithVersion(d))}</span>${dot(d.online)}</button>`).join("")}</div>`;
  } else if (s.settings.layout === "orbit") {
    renderOrbit(box, others);
  } else {
    box.innerHTML = `<div class="tiles">${others.map((d) =>
      `<button class="tile${d.id === selected ? " selected" : ""}" data-id="${esc(d.id)}">` +
      `<span class="top">${glyph(d)}${dot(d.online)}</span><span class="name">${esc(d.name)}</span>` +
      `<span class="dim small">${esc(systems[d.os] ?? "")}</span></button>`).join("")}</div>`;
  }
}

function renderAway(away, inGroup) {
  $("away-switch").hidden = !inGroup;
  $("away").checked = !!away;
  $("away").disabled = state.busy;
  const badge = $("away-badge");
  badge.hidden = !away;
  if (!away) return;
  const bad = !away.hub && away.error;
  badge.textContent = away.hub ? t("hub") : away.through ? t("through the tunnel") : bad ? t("hub unreachable") : t("at home");
  badge.classList.toggle("bad", !!bad);
  badge.title = away.error ?? "";
}

// The orbits: up to six devices on the inner one, the rest on the outer,
// this computer at the centre with the send button.
export function spots(count, radii, cx, cy) {
  if (count === 0) return [];
  const rings = radii.length === 1 ? [[radii[0], count, 0]] : [[radii[0], 6, 0], [radii[1], count - 6, 0.5]];
  const out = [];
  for (const [r, n, turn] of rings) {
    for (let i = 0; i < n; i++) {
      const a = ((i + turn) / n) * 2 * Math.PI - Math.PI / 2;
      out.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
    }
  }
  return out;
}

function renderOrbit(box, others) {
  const w = box.clientWidth, h = box.clientHeight;
  const side = Math.min(w, h), cx = w / 2, cy = h / 2;
  const radii = others.length > 6 ? [side * 0.28, side * 0.43] : [side * 0.36];
  const at = spots(others.length, radii, cx, cy);
  const rings = radii.map((r) => `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--line)"/>`).join("");
  const lines = others.map((d, i) => d.online
    ? `<line x1="${cx}" y1="${cy}" x2="${at[i][0]}" y2="${at[i][1]}" stroke="var(--accent)" stroke-opacity=".35" stroke-width="1.5" stroke-dasharray="4 6"/>` : "").join("");
  box.innerHTML = `<div class="orbit"><svg class="rings">${rings}${lines}</svg>` +
    `<button class="hub" id="orbit-send" style="left:${cx}px;top:${cy}px" ${state.busy ? "disabled" : ""}>⇅<br>${esc(t("Send"))}</button>` +
    others.map((d, i) => `<button class="node${d.id === selected ? " selected" : ""}" data-id="${esc(d.id)}" style="left:${at[i][0]}px;top:${at[i][1]}px">` +
      `${glyph(d, 48)}<span class="name">${esc(d.name)}</span></button>`).join("") + `</div>`;
}

// The details beside the devices, as the phones' summary, then what an
// admin computer may do with it.
function renderDetail() {
  const pane = $("detail");
  const d = state.devices.find((x) => x.id === selected);
  if (!d) {
    selected = null;
    pane.hidden = true;
    return;
  }
  pane.hidden = false;
  const kind = kindOf(d);
  const lines = [[t("Type"), t(kinds[kind])]];
  const sys = systemWithVersion(d);
  if (sys) lines.push([t("Operating system"), sys]);
  if (d.version) lines.push(["Clipboard Bridge", d.version, true]);
  if (d.mac) lines.push([t("MAC address"), d.mac, true]);
  else if (kind === "phone" || kind === "tablet") lines.push([t("MAC address"), t("hidden by the system")]);
  lines.push([t("Role"), t({ phone: "Phone app", lite: "Lite member", shortcut: "Shortcut" }[d.role] ?? "Full member")]);
  const standing = d.self ? (d.admin ? t("This computer · admin") : t("This computer"))
    : d.frozen ? t("frozen") : d.root ? t("root") : d.admin ? t("admin") : "";
  if (standing) lines.push([t("In the group"), standing]);
  if (d.mode) lines.push([t("Sync mode"), modeName(d.mode)]);
  if (!d.online && d.last_seen_ms) lines.push([t("Last seen"), new Date(d.last_seen_ms).toLocaleString(lang)]);
  lines.push([t("Device ID"), d.id, true]);

  const me = state.devices.find((x) => x.self);
  const actions = [];
  if (me?.admin) {
    actions.push(["rename", t("Rename")]);
    if (d.frozen && me.root) actions.push(["unfreeze", t("Unfreeze")]);
    if (!d.self && d.admin && !d.root && !d.frozen && d.role === "full") actions.push(["freeze", t("Freeze"), true]);
    if (me.root && !d.admin && !d.frozen && d.role === "full") actions.push(["admin", t("Make it an admin")]);
    if (!d.self) actions.push(["remove", t("Remove"), true]);
  }
  pane.innerHTML = `<div class="detail-head">${glyph(d, 56)}<div><div class="name">${esc(d.name)}</div>` +
    `<div>${dot(d.online)} <span class="${d.online ? "" : "dim"}">${esc(d.online ? t("online") : t("offline"))}</span></div></div>` +
    `<button class="icon close" id="close" title="${esc(t("Close"))}">✕</button></div>` +
    `<div class="card">${lines.map(([k, v, mono]) => `<div class="line"><span class="dim">${esc(k)}</span><span class="value${mono ? " mono" : ""}">${esc(v)}</span></div>`).join("")}</div>` +
    // An admin sets the mode of a computer that is online; the phones and
    // lite members have no modes yet and refuse.
    (me?.admin && !d.self && d.online && d.role === "full"
      ? `<div class="card"><div class="dim small">${esc(t("Sync mode"))}</div><div class="segmented">${modeButtons(d.mode, d.id)}</div></div>` : "") +
    (me?.admin
      ? `<div class="card actions">${actions.map(([a, label, danger]) => `<button data-action="${a}"${danger ? ' class="danger"' : ""} ${state.busy ? "disabled" : ""}>${esc(label)}</button>`).join("")}</div>`
      : `<p class="dim small">${esc(t("This computer is no admin of the group: the phone or an admin computer adds and removes devices."))}</p>`);
}

// ask shows the confirmation dialog; it resolves to the typed text for a
// field, true for a plain yes, or null.
function ask(title, text, ok, field) {
  return new Promise((resolve) => {
    const dlg = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = ok;
    const input = $("confirm-input");
    input.hidden = field === undefined;
    input.value = field ?? "";
    dlg.onclose = () => resolve(dlg.returnValue === "ok" ? (field === undefined ? true : input.value) : null);
    dlg.returnValue = "";
    dlg.showModal();
    if (field !== undefined) input.select();
  });
}

async function act(method, ...args) {
  state.busy = true;
  render();
  try {
    await call(method, ...args);
  } catch (e) {
    console.error(method, e);
  }
  await refresh();
}

async function deviceAction(action) {
  const d = state.devices.find((x) => x.id === selected);
  if (!d) return;
  switch (action) {
    case "rename": {
      const name = await ask(t("Rename %s", d.name), t("Every device of the group shows the new name."), t("Rename"), d.name);
      if (name && name.trim()) await act("Rename", d.id, name.trim());
      break;
    }
    case "remove":
      if (await ask(t("Remove %s?", d.name), t("It will no longer sync with your devices. To add it again, pair it again."), t("Remove"))) await act("Remove", d.id);
      break;
    case "admin":
      if (await ask(t("Make %s an admin?", d.name), t("It can then add and remove devices with cbb pair and cbb revoke. Its key is a file on the computer, so do this only for a computer you keep safe."), t("Make it an admin"))) await act("MakeAdmin", d.id);
      break;
    case "freeze":
      if (await ask(t("Freeze %s?", d.name), t("For a stolen admin computer: it changes nothing more and the others refuse it until the root unfreezes or removes it."), t("Freeze"))) await act("Freeze", d.id);
      break;
    case "unfreeze":
      if (await ask(t("Unfreeze %s?", d.name), t("Unfreeze it only if it is in safe hands; otherwise remove it."), t("Unfreeze"))) await act("Unfreeze", d.id);
      break;
  }
}

async function saveSettings(change) {
  state.settings = { ...state.settings, ...change };
  applyTheme();
  render();
  renderSettings();
  try {
    await call("SaveSettings", state.settings);
  } catch (e) {
    console.error("settings", e);
  }
}

function renderSettings() {
  const s = state.settings;
  $("swatches").innerHTML = colors.map((c) => {
    const dark = s.appearance === "dark" || (s.appearance !== "light" && darkQuery.matches);
    return `<button type="button" data-color="${c.name}" aria-checked="${c.name === s.color}" style="background:${(dark ? c.dark : c.light).accent}" ` +
      `title="${esc(t(c.name[0].toUpperCase() + c.name.slice(1)))}"></button>`;
  }).join("");
  for (const b of document.querySelectorAll("[data-appearance]")) b.setAttribute("aria-checked", String(b.dataset.appearance === s.appearance));
  $("details").checked = s.details ?? state.show_details;
  const mode = state.status?.group && !state.status.removed ? state.status.mode : "";
  $("mode-settings").hidden = !mode;
  $("modes").innerHTML = mode ? modeButtons(mode, "") : "";
  $("version").textContent = state.version;
}

async function refresh() {
  try {
    state = await call("State");
  } catch (e) {
    console.error("state", e);
    return;
  }
  await loadLanguage(state.lang);
  applyTheme();
  render();
}

document.addEventListener("click", async (e) => {
  const el = e.target.closest("button, input");
  if (!el || !state) return;
  if (el.dataset.layout) return saveSettings({ layout: el.dataset.layout });
  if (el.dataset.color) return saveSettings({ color: el.dataset.color });
  if (el.dataset.appearance) return saveSettings({ appearance: el.dataset.appearance });
  if (el.dataset.action) return deviceAction(el.dataset.action);
  if (el.dataset.mode) {
    await act("SetMode", el.dataset.modeFor, el.dataset.mode);
    return renderSettings();
  }
  if (el.dataset.id) {
    selected = el.dataset.id;
    return render();
  }
  switch (el.id) {
    case "close": selected = null; return render();
    case "send": case "orbit-send": return act("Send");
    case "fetch": return act("Fetch");
    case "add": return $("add-dialog").showModal();
    case "settings": renderSettings(); return $("settings-dialog").showModal();
  }
});

$("away").addEventListener("change", async (e) => {
  e.preventDefault();
  const on = e.target.checked;
  e.target.checked = !on;
  if (on && !(await ask(t("Turn sync away from home on?"),
    t("This computer then reaches the group's hub from the internet through the group's own WireGuard tunnel, the clipboard encrypted end to end. Its keys are files: encrypt the disk, keep the service's folder out of unencrypted backups, and remove the computer at once if it is lost."),
    t("Turn on")))) return;
  await act("SetAway", on);
});

$("details").addEventListener("change", (e) => saveSettings({ details: e.target.checked }));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && selected && !document.querySelector("dialog[open]")) {
    selected = null;
    render();
  }
});
addEventListener("resize", () => state && state.settings.layout === "orbit" && render());

refresh();
setInterval(() => !document.querySelector("dialog[open]") && refresh(), 4000);
