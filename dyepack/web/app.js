// mine map: live from /events or a replay of sample_events.json (index.html?replay=1)
const SPEED_ROWS_PER_MIN = 600; // same as schema.py
const SPEED_FILES_PER_MIN = 30; // same as schema.py
const TABLE_ROWS = 50000;
const CANARIES = 200;
const VEINS = 5;
const WINDOW = 180; // seconds on the speed chart
const REPLAY = new URLSearchParams(location.search).has("replay");
// control token for respond and alert route changes: read once from ?token= then dropped from the address bar
const TOKEN = (() => {
  const q = new URLSearchParams(location.search);
  const t = q.get("token") || "";
  if (q.has("token")) {
    q.delete("token");
    const rest = q.toString();
    history.replaceState(null, "", `${location.pathname}${rest ? `?${rest}` : ""}${location.hash}`);
  }
  return t;
})();
const ALL = ["status", "chart", "mine", "drive", "feed", "incidents", "score", "prints", "phone"];
const RANK = { info: 0, low: 1, high: 2, critical: 3 };
const ROUTES = { critical: ["push", "sms"], high: ["push"], low: [] };
const CHANNELS = { push: "Phone push", sms: "SMS", email: "Email", discord: "Discord" };
// button, done label, feed line
const ACTIONS = {
  lock: ["Lock", "Locked", "Locked from the dashboard"],
  revoke: ["Revoke key", "Key revoked", "Revoked the stolen key"],
  notify_customers: ["Draft breach notice", "Notice drafted", "Drafted a breach notice"],
  dismiss: ["Dismiss", "Dismissed", "Marked as a false alarm"],
};
// the demo drive from drive.py (no route lists it yet). decoys sort first in their folders
// like they do on disk. other files show up once they get opened
const DRIVE = [
  ["customers", ["all_customers_full_export_2026.csv", "customers.csv"]],
  ["billing", ["all_accounts_2026_with_payment_info.json", "invoices_2026_10.json"]],
  ["support", ["notes.md"]],
  ["backups", ["all_customers_backup_unencrypted.csv", "nightly_2026_11_13.dye"]],
  ["config", [".env.production"]],
];
const DECOYS = ["all_customers_full_export_2026.csv", "all_accounts_2026_with_payment_info.json", "all_customers_backup_unencrypted.csv", ".env.production"];

const $ = (id) => document.getElementById(id);
const fmt = (n) => Math.round(n).toLocaleString("en-US");
// seconds above one, milliseconds below
function dur(s, short, coarse) {
  s = Math.max(0, Number(s) || 0);
  if (s >= 0.9995) return `${s.toFixed(1)} s`;
  const ms = Math.round(s * 1000);
  const floor = coarse ? 5 : 1; // drill times come in hundredths. their zero means under 5 ms
  return ms ? `${ms} ms` : short ? `<${floor} ms` : `under ${floor} ms`;
}
const later = (s) => (s < 0.0005 ? "at the same moment" : `${dur(s)} later`);
const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : "");
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" });
const mmss = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const serious = (e) => e.severity === "high" || e.severity === "critical";
const steps = (p) => String(p || "").split("/").filter(Boolean);
const fileName = (p) => steps(p).at(-1) || "unknown file";
const folderOf = (p) => steps(p).at(-2) || "drive";
const diamond = (x, y, r) => `M${x},${y - r}L${x + r},${y}L${x},${y + r}L${x - r},${y}Z`;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function svg(tag, attrs = {}, text) {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text != null) n.textContent = text;
  return n;
}

// a ring of dye that spreads once from a spot
function boom(root, [x, y]) {
  const ring = svg("circle", { cx: x.toFixed(1), cy: y.toFixed(1), r: 12, class: "boom" });
  root.append(ring);
  setTimeout(() => ring.remove(), 1400);
}

// restart a css animation
function retrigger(node, cls) {
  if (!node) return;
  node.classList.remove(cls);
  node.getBoundingClientRect();
  node.classList.add(cls);
}

// canary spots along the veins, the same on every load
const MARKERS = (() => {
  let seed = 7;
  const rand = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const per = CANARIES / VEINS;
  return Array.from({ length: CANARIES }, (_, i) => ({
    v: i % VEINS,
    u: (Math.floor(i / VEINS) + 0.2 + rand() * 0.6) / per,
    side: rand() < 0.5 ? -1 : 1,
  }));
})();

// words

const REASONS = {
  canary_touch: (d) => {
    const n = d.canary_ids?.length || 1;
    return n === 1 ? "Touched a canary customer" : `Touched ${n} canary customers`;
  },
  speed: (d, e) => {
    const unit = S.procs.has(e.session) ? "files" : "rows";
    return d.rate_per_min ? `Tripped the speed alarm at ${fmt(d.rate_per_min)} ${unit} a minute` : "Tripped the speed alarm";
  },
  canary_login: () => "Tried to log in as a canary customer",
  unknown_account_login: () => "Tried to log in to an account that doesn't exist",
  canary_contact: () => "Emailed or called a canary customer",
  decoy_open: () => "Opened a decoy file",
};
const what = (e) => (REASONS[e.detail?.reason] || ((d) => d.reason || "Alarm"))(e.detail || {}, e);

function who(e) {
  const p = S.procs.get(e.session);
  if (p) return procLabel(p);
  return `${e.actor || "someone"} from ${e.ip || "an unknown address"}`;
}

// linux file events carry no process name or pid. say that plainly
function procLabel(p) {
  const named = p.name && p.name !== "unknown";
  const host = p.host && !["127.0.0.1", "localhost", "::1"].includes(p.host) ? ` on ${p.host}` : "";
  return `${named ? p.name : "Unknown process"}${p.pid != null ? ` (pid ${p.pid})` : ""}${host}`;
}

function why(e) {
  const d = e.detail || {};
  if (d.export_id) return `That canary only exists in export ${d.export_id}.`;
  if (d.reason === "unknown_account_login") return "The name likely came from a fake list that a wrong password opened.";
  if (d.reason === "decoy_open") return e.file ? `${fileName(e.file)} is a decoy. No real work ever opens it.` : "No real work ever opens a decoy file.";
  return "";
}

function lockText(e) {
  const w = e.detail?.what || "session";
  if (w === "ip") return `Address ${e.ip} locked`;
  if (w === "session") return `Session ${e.session} locked`;
  return `${cap(w)} locked`;
}

function holdText(e) {
  if (e.type === "action") return `${ACTIONS[e.detail.action]?.[2] || cap(e.detail.action)} · ${e.detail.incident}`;
  return e.detail?.what === "ip" ? lockText(e) : `${lockText(e)} · ${who(e)}`;
}

// state

let S;
function fresh() {
  S = {
    now: 0, rate: 0, ticks: [], seen: 0,
    phases: {}, phase: null,
    sessions: new Map(), // table readers, each digs a tunnel
    first: new Map(), // session -> first event
    firstRead: new Map(), // session -> first read
    procs: new Map(), // drive readers seen by the sentinel
    folders: new Map(), // drive folder -> {files, sealed}
    reader: null,
    incidents: new Map(), exports: new Map(),
    feed: [], notes: [], score: {},
    hits: new Set(), flash: [], pings: [], bursts: [], booms: [],
    copies: new Map(), // session -> honey locked exports it downloaded
    lastHold: null,
    live: { normalAlarms: 0, firstRead: null, exposed: 0 },
    timed: {}, // heist-1 and agent: when the step started, its incident, its time to catch
  };
  for (const [name, files] of DRIVE) for (const file of files) driveFile(name, file);
}

function folder(name) {
  if (!S.folders.has(name)) S.folders.set(name, { files: new Map(), sealed: false });
  return S.folders.get(name);
}

function driveFile(name, file) {
  const files = folder(name).files;
  if (!files.has(file)) {
    const kind = DECOYS.includes(file) ? "decoy" : /\.(csv|json)$/i.test(file) ? "data" : /\.dye$/i.test(file) ? "locked" : "other";
    files.set(file, { kind, opens: 0, fired: false, sealed: false });
  }
  return files.get(file);
}

function incident(id = "unknown") {
  if (!S.incidents.has(id)) {
    S.incidents.set(id, {
      id, alarms: [], sessions: new Set(), severity: "info", alarmAt: null, last: null,
      heldAt: null, firstHold: null, locked: false, seals: [], notes: [], actions: new Set(),
      report: null, dismissed: false,
    });
  }
  return S.incidents.get(id);
}

function hold(inc, e) {
  inc.heldAt = e.ts;
  inc.firstHold ??= e;
  S.lastHold = e;
}

// light up the next k canaries along this reader's tunnel
function touch(s, k) {
  if (!k) return;
  const at = (s.rows / TABLE_ROWS) * VEINS;
  const ahead = [];
  MARKERS.forEach((m, i) => {
    const pos = ((m.v - s.vein + VEINS) % VEINS) + m.u;
    if (pos >= at && !S.hits.has(i)) ahead.push([pos, i]);
  });
  ahead.sort((a, b) => a[0] - b[0]);
  for (const [, i] of ahead.slice(0, k)) {
    S.hits.add(i);
    S.flash.push(i);
  }
}

function tableRead(e, d) {
  if (String(d.path || "").startsWith("/api/exports/")) {
    // a download of a honey locked export: the copy leaves as a crate, the mine isn't dug
    const list = S.copies.get(e.session) || [];
    list.push({ id: fileName(d.path), real: Math.max(0, (d.rows || 0) - (d.canaries || 0)) });
    S.copies.set(e.session, list);
    return dirty("incidents");
  }
  let s = S.sessions.get(e.session);
  if (!s) S.sessions.set(e.session, (s = { actor: e.actor, rows: 0, canaries: 0, vein: S.sessions.size % VEINS }));
  touch(s, d.canaries || 0);
  s.rows += d.rows || 0;
  s.canaries += d.canaries || 0;
  if (S.phase === "heist-1") {
    S.live.firstRead ??= e.ts;
    S.live.exposed += (d.rows || 0) - (d.canaries || 0);
  }
  dirty("mine", "score", "incidents");
}

function fileRead(e, d) {
  let p = S.procs.get(e.session);
  if (!p) S.procs.set(e.session, (p = { name: d.process || e.actor || "unknown", pid: d.pid, host: e.ip, fpm: 0, peak: 0, opens: [] }));
  const where = folderOf(d.path);
  let name = fileName(d.path);
  // after a burst, customers.csv.dye is the same file locked in place
  if (/\.dye$/i.test(name) && folder(where).files.get(name.slice(0, -4))?.sealed) name = name.slice(0, -4);
  driveFile(where, name).opens++;
  p.opens.push({ where, name, sealed: folder(where).sealed });
  if (p.opens.length > 2000) p.opens.shift();
  p.fpm = d.files_per_min || 0;
  p.peak = Math.max(p.peak, p.fpm);
  p.last = d.path;
  p.lastTs = e.ts;
  S.reader = e.session;
  S.pings.push(`${where}/${name}`);
  dirty("drive", "incidents");
}

function alarm(e, d) {
  const inc = incident(d.incident);
  inc.alarms.push(e);
  if (e.session) inc.sessions.add(e.session);
  if ((RANK[e.severity] ?? 0) > (RANK[inc.severity] ?? 0)) inc.severity = e.severity;
  if (d.reason === "decoy_open") {
    // remember which file it was, the reader moves on
    e.file = d.path || S.procs.get(e.session)?.last || null;
    if (e.file) {
      const f = driveFile(folderOf(e.file), fileName(e.file));
      f.kind = "decoy";
      f.fired = true;
      S.booms.push({ at: "file", id: `${folderOf(e.file)}/${fileName(e.file)}` });
    }
  }
  if (serious(e)) {
    inc.alarmAt = e.ts;
    inc.last = e;
    if (S.phase === "normal") S.live.normalAlarms++;
    const step = S.timed[S.phase];
    if (step && step.inc == null && step.start != null) {
      // timed like the drill: from the step's start, to the hundredth
      step.live = Math.round((e.ts - step.start) * 100) / 100;
      step.inc = d.incident;
    }
  }
  const s = S.sessions.get(e.session);
  if (s && !s.alarmed) S.booms.push({ at: "session", id: e.session });
  if (s) s.alarmed = true;
  const x = S.exports.get(d.export_id);
  if (x && !x.hits) S.booms.push({ at: "crate", id: d.export_id });
  if (x) x.hits++;
  S.feed.unshift(e);
  dirty("status", "feed", "mine", "drive", "score", "prints", "incidents");
}

function handle(e) {
  const d = e.detail || {};
  S.now = Math.max(S.now, e.ts || 0);
  S.seen++;
  if (e.session && !S.first.has(e.session)) S.first.set(e.session, e.ts);
  if (e.type === "read" && e.session && !S.firstRead.has(e.session)) S.firstRead.set(e.session, e.ts);
  switch (e.type) {
    case "tick":
      S.rate = d.reads_per_min || 0;
      S.ticks.push([e.ts, S.rate]);
      while (S.ticks.length && S.ticks[0][0] < S.now - WINDOW - 5) S.ticks.shift();
      dirty("chart", "drive", "phone");
      break;
    case "read":
      if (d.process != null || d.files_per_min != null) fileRead(e, d);
      else tableRead(e, d);
      break;
    case "alarm":
      alarm(e, d);
      break;
    case "lock": {
      const inc = incident(d.incident);
      inc.locked = true;
      hold(inc, e);
      const s = S.sessions.get(e.session);
      if (s && (d.what || "session") === "session") s.locked = true;
      S.feed.unshift(e);
      dirty("status", "feed", "mine", "incidents");
      break;
    }
    case "burst": {
      const name = fileName(d.folder);
      folder(name).sealed = true;
      for (const file of d.files || []) {
        // files get locked where they sit, customers.csv turns into customers.csv.dye
        const f = driveFile(name, file.replace(/\.dye$/i, ""));
        f.sealed = true;
        f.lockedAs = file;
      }
      incident(d.incident).seals.push({ folder: name, ts: e.ts, files: d.files || [] });
      S.bursts.push(name);
      S.feed.unshift(e);
      dirty("drive", "feed", "incidents");
      break;
    }
    case "notify":
      incident(d.incident).notes.push(e);
      S.notes.unshift(e);
      dirty("phone", "incidents");
      break;
    case "action": {
      const inc = incident(d.incident);
      if (Array.isArray(d.checklist)) inc.checklist = d.checklist;
      if (inc.actions.has(d.action)) {
        dirty("incidents"); // already shown, like a click the server echoes back
        break;
      }
      inc.actions.add(d.action);
      if (d.action === "dismiss") inc.dismissed = true;
      if (d.action === "lock") inc.locked = true;
      if (d.action === "lock" || d.action === "revoke") hold(inc, e);
      S.feed.unshift(e);
      dirty("status", "feed", "incidents");
      break;
    }
    case "export":
      S.exports.set(d.export_id, { rows: d.rows, canaries: d.canaries, actor: e.actor, ts: e.ts, phase: S.phase, hits: 0 });
      dirty("mine", "prints");
      break;
    case "report":
      incident(d.incident).report = { ...d, ts: e.ts };
      dirty("incidents");
      break;
    case "drill": {
      S.phases[d.phase] = d.status;
      if (d.status === "start") S.phase = d.phase;
      else if (S.phase === d.phase) S.phase = null;
      const timed = d.phase === "heist-1" || d.phase === "agent";
      if (timed && d.status === "start") S.timed[d.phase] = { start: e.ts, inc: null, live: null, drill: null };
      // each drill run scores its own steps. a time to catch only counts for the step that measured it
      for (const [k, v] of Object.entries(d.score || {})) {
        if (k === "detect_seconds") {
          if (timed && d.status === "end") (S.timed[d.phase] ??= { start: null, inc: null, live: null }).drill = v;
        } else if (k !== "rows_exposed" || d.phase === "heist-1") S.score[k] = v;
      }
      dirty("status", "score", "mine", "incidents");
      break;
    }
  }
  if (S.feed.length > 60) S.feed.length = 60;
}

// drawing, batched so a burst of events paints once

const pending = new Set();
let timer = 0;
function dirty(...parts) {
  for (const p of parts) pending.add(p);
  timer ||= setTimeout(flush, 40);
}

function flush() {
  timer = 0;
  const parts = new Set(pending);
  pending.clear();
  const draw = {
    status: drawStatus, chart: drawChart, mine: drawMine, drive: drawDrive, feed: drawFeed,
    incidents: drawIncidents, score: drawScore, prints: drawPrints, phone: drawPhone,
  };
  for (const p of ALL) if (parts.has(p)) draw[p]();
}

const WORDS = { clear: "All clear", alarm: "Alarm", locked: "Locked" };
let lastMood = "clear";

function drawStatus() {
  let open = null, held = false, dismissed = false;
  for (const i of S.incidents.values()) {
    if (i.dismissed) dismissed = true;
    else if (i.alarmAt != null && (i.heldAt == null || i.heldAt < i.alarmAt)) {
      if (!open || i.alarmAt > open.alarmAt) open = i;
    } else if (i.heldAt != null) held = true;
  }
  const m = open ? "alarm" : held ? "locked" : "clear";
  const box = $("status");
  box.dataset.state = m;
  $("status-word").textContent = WORDS[m];
  let line = !S.seen ? "Waiting for the first events." : dismissed ? "No open alarms." : "No alarms so far.";
  if (open) line = `${what(open.last)} · ${who(open.last)}`;
  else if (held && S.lastHold) line = holdText(S.lastHold);
  $("status-line").textContent = line;
  document.body.dataset.mood = m;
  if (m === "alarm" && lastMood !== "alarm") {
    retrigger(box, "burst");
    retrigger($("bloom"), "go");
  }
  lastMood = m;
  for (const li of $("phases").children) {
    const st = S.phases[li.dataset.phase];
    li.dataset.state = st === "start" ? "now" : st === "end" ? "done" : "";
  }
}

function drawChart() {
  const rate = $("rate");
  rate.textContent = fmt(S.rate);
  rate.classList.toggle("over", S.rate > SPEED_ROWS_PER_MIN);
  const box = $("chart");
  const w = box.clientWidth, h = box.clientHeight;
  if (!w || !h) return;
  const L = 42, R = 12, T = 12, B = 22;
  const pw = w - L - R, ph = h - T - B;
  const t0 = S.now - WINDOW;
  const pts = S.ticks.filter(([t]) => t >= t0);
  // log scale so a normal day, the limit and a heist all fit
  const top = Math.max(5, Math.ceil(Math.log10(Math.max(0, ...pts.map((p) => p[1])) + 1)));
  const y = (v) => T + ph * (1 - Math.log10(Math.max(0, v) + 1) / top);
  const x = (t) => L + (pw * (t - t0)) / WINDOW;
  const limit = y(SPEED_ROWS_PER_MIN);
  const cut = ((limit - T) / ph).toFixed(4);

  const g = svg("svg", { width: w, height: h, viewBox: `0 0 ${w} ${h}`, "aria-hidden": "true" });
  const ink = svg("linearGradient", { id: "speed-ink", gradientUnits: "userSpaceOnUse", x1: 0, y1: T, x2: 0, y2: T + ph });
  for (const [off, c] of [[0, "--dye"], [cut, "--dye"], [cut, "--gold-hi"], [1, "--gold-hi"]]) {
    ink.append(svg("stop", { offset: off, style: `stop-color: var(${c})` }));
  }
  const defs = svg("defs");
  defs.append(ink);
  g.append(defs);
  for (let k = 0; k <= top; k++) {
    const v = k ? 10 ** k : 0, yy = y(v);
    g.append(
      svg("line", { x1: L, x2: w - R, y1: yy, y2: yy, class: "grid" }),
      svg("text", { x: L - 7, y: yy + 4, "text-anchor": "end", class: "tick" }, v >= 1000 ? `${v / 1000}k` : String(v)),
    );
  }
  for (const m of [60, 120]) g.append(svg("line", { x1: x(t0 + m), x2: x(t0 + m), y1: T, y2: T + ph, class: "grid" }));
  if (pts.length > 1) {
    const line = pts.map(([t, v], i) => `${i ? "L" : "M"}${x(t).toFixed(1)},${y(v).toFixed(1)}`).join("");
    const base = (T + ph).toFixed(1);
    g.append(
      svg("path", { d: `${line}L${x(pts.at(-1)[0]).toFixed(1)},${base}L${x(pts[0][0]).toFixed(1)},${base}Z`, class: "area", fill: "url(#speed-ink)" }),
      svg("path", { d: line, class: "line", stroke: "url(#speed-ink)" }),
    );
  }
  g.append(
    svg("line", { x1: L, x2: w - R, y1: limit, y2: limit, class: "limit" }),
    svg("text", { x: w - R, y: limit - 7, "text-anchor": "end", class: "limit-label" }, `Machine speed ${fmt(SPEED_ROWS_PER_MIN)}`),
    svg("text", { x: L, y: h - 4, class: "tick" }, "3 min ago"),
    svg("text", { x: w - R, y: h - 4, "text-anchor": "end", class: "tick" }, "now"),
  );
  box.replaceChildren(g);
}

const SPLATS = [[0.3, 0.42, 0.3], [0.7, 0.62, 0.24], [0.52, 0.14, 0.13], [0.88, 0.28, 0.11], [0.14, 0.84, 0.14]];

// a wooden crate whose dye stains show once it's marked
function crateArt(x, y, cw, ch) {
  const g = svg("g", { class: "crate", transform: `translate(${x},${y})` });
  const stain = svg("g", { class: "stain" });
  const size = Math.min(cw, ch * 1.4); // keeps the splats on short crates
  for (const [cx, cy, r] of SPLATS) stain.append(svg("circle", { cx: cw * cx, cy: ch * cy, r: size * r }));
  stain.append(svg("rect", { x: cw * 0.64, y: ch * 0.7, width: 3, height: ch * 0.6, rx: 1.5 }));
  g.append(
    svg("rect", { width: cw, height: ch, rx: 2, class: "box" }),
    svg("path", { d: `M1,${ch / 3}H${cw - 1}M1,${(ch * 2) / 3}H${cw - 1}`, class: "plank" }),
    stain,
  );
  return g;
}

// the mine: a cross section of the customer table, rebuilt when its width changes

let M = null;

function layoutMine() {
  const box = $("mine");
  const w = Math.floor(box.clientWidth);
  if (!w || (M && M.w === w)) return;
  const narrow = w < 560;
  const h = Math.round(Math.min(360, Math.max(250, w * 0.27)));
  const sy = Math.round(h * 0.24); // ground line
  const sx = narrow ? 22 : 40; // shaft
  const x0 = sx + 16, x1 = w - (narrow ? 10 : 20);
  const amp = (h - sy) / 30;
  const depth = (v) => sy + (h - sy) * (0.16 + (0.72 * v) / (VEINS - 1));
  const pt = (v, u) => [x0 + (x1 - x0) * u, depth(v) + amp * Math.sin(u * 6.3 + v * 2.1) + amp * 0.45 * Math.sin(u * 15.7 + v)];
  const trace = (f, a, b) => {
    const n = Math.max(2, Math.ceil((b - a) * 64));
    let d = "";
    for (let i = 0; i <= n; i++) {
      const [px, py] = f(a + ((b - a) * i) / n);
      d += `${i ? "L" : "M"}${px.toFixed(1)},${py.toFixed(1)}`;
    }
    return d;
  };
  const vein = (v, a, b) => trace((u) => pt(v, u), a, b);

  const root = svg("svg", { width: w, height: h, viewBox: `0 0 ${w} ${h}`, role: "img", class: narrow ? "narrow" : "" });
  root.append(svg("rect", { width: w, height: sy, class: "sky" }), svg("rect", { y: sy, width: w, height: h - sy, class: "rock" }));
  for (let v = 0; v < VEINS - 1; v++) {
    const mid = (u) => [pt(v, u)[0], (pt(v, u)[1] + pt(v + 1, u)[1]) / 2 + amp * 0.7 * Math.sin(u * 9 + v * 3)];
    root.append(svg("path", { d: trace(mid, -0.1, 1.1), class: "strata" }));
  }
  root.append(svg("rect", { x: sx - 5, y: sy, width: 10, height: depth(VEINS - 1) + amp * 2 + 10 - sy, class: "shaft" }));
  for (let v = 0; v < VEINS; v++) {
    const d = vein(v, 0, 1);
    root.append(
      svg("path", { d: `M${sx},${pt(v, 0)[1].toFixed(1)}H${x0}`, class: "adit" }),
      svg("path", { d, class: "vein-glow" }),
      svg("path", { d, class: "vein" }),
      svg("path", { d, class: "vein-fleck" }),
    );
  }
  const tunnels = svg("g");
  const markLayer = svg("g");
  const crateLayer = svg("g");
  const marks = MARKERS.map((m) => {
    const [px, py] = pt(m.v, m.u);
    const c = svg("circle", { cx: px.toFixed(1), cy: (py + m.side * (narrow ? 3 : 4.5)).toFixed(1), r: narrow ? 2 : 2.7, class: "canary" });
    markLayer.append(c);
    return c;
  });
  const top = sy - (narrow ? 26 : 38);
  root.append(
    tunnels,
    markLayer,
    svg("path", { d: `M0,${sy}H${w}`, class: "ground" }),
    svg("path", { d: `M${sx - 13},${sy}L${sx},${top}L${sx + 13},${sy}M${sx - 7},${sy - 13}H${sx + 7}M${sx},${top}V${sy}`, class: "headframe" }),
    svg("circle", { cx: sx, cy: top, r: narrow ? 5 : 7, class: "headframe" }),
    svg("text", { x: w - (narrow ? 10 : 20), y: narrow ? 18 : 26, "text-anchor": "end", class: "sky-label" }, `${fmt(TABLE_ROWS)} customers · ${CANARIES} canaries`),
    crateLayer,
  );
  M = { w, sy, sx, x0, x1, narrow, pt, vein, root, tunnels, marks, crateLayer, crates: new Map(), cratePos: new Map() };
  box.replaceChildren(root);
  drawMine();
}

function drawMine() {
  if (!M) return;
  const { pt, vein, narrow } = M;
  M.tunnels.replaceChildren();
  const heads = new Map();
  let read = 0;
  for (const [id, s] of S.sessions) {
    read += s.rows;
    let left = (s.rows / TABLE_ROWS) * VEINS, v = s.vein, end = null;
    for (let n = 0; left > 0 && n < VEINS; n++, v = (v + 1) % VEINS, left -= 1) {
      const len = Math.min(1, Math.max(left, 6 / (M.x1 - M.x0)));
      M.tunnels.append(svg("path", { d: vein(v, 0, len), class: "dug" }));
      end = pt(v, len);
    }
    if (!end) continue;
    heads.set(id, end);
    const state = s.locked ? "locked" : s.alarmed ? "alarmed" : "digging";
    const [ex, ey] = end;
    M.tunnels.append(svg("circle", { cx: ex.toFixed(1), cy: ey.toFixed(1), r: narrow ? 3 : 4.5, class: `head ${state}` }));
    if (s.locked) M.tunnels.append(svg("rect", { x: (ex + 5).toFixed(1), y: (ey - 11).toFixed(1), width: 5, height: 22, rx: 1.5, class: "gate" }));
    if (state !== "digging") {
      const flip = ex > M.w - 150;
      M.tunnels.append(svg("text", { x: (ex + (flip ? -8 : 0)).toFixed(1), y: (ey - 15).toFixed(1), "text-anchor": flip ? "end" : "start", class: "tag" }, s.locked ? `${s.actor} · locked` : s.actor));
    }
  }
  M.marks.forEach((c, i) => c.classList.toggle("hit", S.hits.has(i)));
  for (const i of S.flash) retrigger(M.marks[i], "flash");
  S.flash = [];
  drawCrates();
  const later = [];
  for (const b of S.booms) {
    const at = b.at === "session" ? heads.get(b.id) : b.at === "crate" ? M.cratePos.get(b.id) : null;
    if (at) boom(M.root, at);
    else if (b.at === "file") later.push(b);
  }
  S.booms = later;
  M.root.setAttribute("aria-label", `Customer table drawn as a mine: ${fmt(read)} rows read, ${S.hits.size} canaries touched, ${S.exports.size} exports made.`);
}

function drawCrates() {
  const { narrow } = M;
  const cw = narrow ? 34 : 48, ch = narrow ? 24 : 34, gap = narrow ? 14 : 26;
  const left = M.sx + (narrow ? 26 : 44);
  const fit = Math.max(1, Math.floor((M.w - left - 8) / (cw + gap)));
  const shown = [...S.exports.keys()].slice(-fit);
  for (const [id, g] of M.crates) {
    if (!shown.includes(id)) {
      g.remove();
      M.crates.delete(id);
    }
  }
  shown.forEach((id, k) => {
    const x = S.exports.get(id);
    let g = M.crates.get(id);
    if (!g) {
      g = crateArt(0, 0, cw, ch);
      g.append(
        svg("text", { x: cw / 2, y: ch / 2 + 5, "text-anchor": "middle", class: "stencil" }, String(id).toUpperCase()),
        svg("text", { x: cw / 2, y: -8, "text-anchor": "middle", class: "note" }),
      );
      M.crateLayer.append(g);
      M.crates.set(id, g);
    }
    g.setAttribute("transform", `translate(${left + k * (cw + gap)},${M.sy - ch})`);
    M.cratePos.set(id, [left + k * (cw + gap) + cw / 2, M.sy - ch / 2]);
    const cracking = S.phase === "heist-2" && x.phase === "heist-2" && !x.hits;
    g.classList.toggle("leaked", x.hits > 0);
    g.classList.toggle("cracking", cracking);
    g.lastChild.textContent = x.hits ? "LEAKED" : cracking ? "CRACKING" : "";
  });
}

// the drive: each folder is a shaft, rebuilt when its width or file list changes

let D = null;

function layoutDrive() {
  const box = $("drive");
  const w = Math.floor(box.clientWidth);
  const list = [...S.folders].slice(0, 7);
  const key = `${w}|${list.map(([n, f]) => `${n}:${[...f.files.keys()].join(",")}`).join("|")}`;
  if (!w || (D && D.key === key)) return;
  const narrow = w < 400;
  const bh = narrow ? 22 : 26, gap = 9, sy = 40;
  const most = Math.max(2, ...list.map(([, f]) => f.files.size));
  const h = Math.max(190, sy + 14 + most * (bh + gap) + 34);
  const span = w / list.length;
  const sw = Math.min(72, span - 12);
  const root = svg("svg", { width: w, height: h, viewBox: `0 0 ${w} ${h}`, role: "img", class: narrow ? "narrow" : "" });
  root.setAttribute("aria-label", `Company drive with ${list.length} folders drawn as mine shafts.`);
  root.append(svg("rect", { width: w, height: sy, class: "sky" }), svg("rect", { y: sy, width: w, height: h - sy, class: "rock" }), svg("path", { d: `M0,${sy}H${w}`, class: "ground" }));
  const folders = new Map(), files = new Map(), centers = new Map();
  list.forEach(([name, f], i) => {
    const cx = span * (i + 0.5);
    const g = svg("g", { class: "folder" });
    g.append(svg("rect", { x: cx - sw / 2, y: sy, width: sw, height: h - sy - 26, rx: 3, class: "shaft" }));
    [...f.files.keys()].forEach((file, k) => {
      const bw = sw - 12, x = cx - bw / 2, y = sy + 12 + k * (bh + gap);
      const fg = svg("g", { class: "file" });
      fg.append(
        svg("title", {}, `${name}/${file}`),
        svg("rect", { x, y, width: bw, height: bh, rx: 3, class: "ore" }),
        svg("path", { d: diamond(cx, y + bh / 2, bh * 0.34), class: "mark" }),
        crateArt(x, y, bw, bh),
        svg("text", { x: cx, y: y + bh / 2 + 4, "text-anchor": "middle", class: "dye-tag" }, ".dye"),
      );
      g.append(fg);
      files.set(`${name}/${file}`, fg);
      centers.set(`${name}/${file}`, [cx, y + bh / 2]);
    });
    g.append(
      svg("text", { x: cx, y: sy - 13, "text-anchor": "middle", class: "sign" }, name),
      svg("text", { x: cx, y: h - 9, "text-anchor": "middle", class: "sealed-tag" }, "LOCKED"),
      svg("circle", { cx, cy: sy + 30, r: 14, class: "ring" }),
    );
    root.append(g);
    folders.set(name, g);
  });
  D = { key, root, folders, files, centers };
  box.replaceChildren(root);
}

function drawDrive() {
  layoutDrive();
  if (D) {
    for (const [name, f] of S.folders) {
      D.folders.get(name)?.classList.toggle("sealed", f.sealed);
      for (const [file, x] of f.files) {
        const g = D.files.get(`${name}/${file}`);
        if (!g) continue;
        for (const k of ["data", "decoy", "locked", "other"]) g.classList.toggle(k, x.kind === k);
        g.classList.toggle("opened", x.opens > 0);
        g.classList.toggle("fired", x.fired);
        g.classList.toggle("sealed", x.sealed && x.kind !== "decoy");
        g.firstChild.textContent = x.sealed && x.lockedAs ? `${name}/${x.lockedAs}, locked in place` : `${name}/${file}`;
      }
    }
    for (const k of S.pings) retrigger(D.files.get(k), "ping");
    for (const name of S.bursts) retrigger(D.folders.get(name), "burst");
    for (const b of S.booms) if (b.at === "file" && D.centers.has(b.id)) boom(D.root, D.centers.get(b.id));
    S.pings = [];
    S.bursts = [];
    S.booms = S.booms.filter((b) => b.at !== "file");
  }
  const p = S.procs.get(S.reader);
  const idle = !p || S.now - p.lastTs > 10;
  $("proc-name").textContent = p ? who({ session: S.reader }) : "Nobody yet";
  $("proc-last").textContent = p ? `Last file: ${folderOf(p.last)}/${fileName(p.last)}` : "Every file open on the drive shows up here.";
  const fpm = $("proc-fpm");
  fpm.textContent = fmt(idle ? 0 : p.fpm);
  fpm.classList.toggle("over", !idle && p.fpm > SPEED_FILES_PER_MIN);
  $("proc-unit").textContent = p && idle ? `files a minute now, peak ${fmt(p.peak)}` : "files a minute";
  const pace = $("proc-pace");
  pace.hidden = !p;
  if (p) {
    const fast = p.peak > SPEED_FILES_PER_MIN;
    pace.dataset.pace = fast ? "machine" : "human";
    pace.textContent = fast ? "Machine speed: a script or AI agent" : "Human speed: likely a person";
  }
}

let topSeen = null;

function drawFeed() {
  const list = $("feed");
  list.replaceChildren(...S.feed.slice(0, 40).map(feedItem));
  if (S.feed[0] && S.feed[0] !== topSeen) list.firstChild.classList.add("new");
  topSeen = S.feed[0] || null;
  $("feed-empty").hidden = S.feed.length > 0;
}

function feedItem(e) {
  const d = e.detail || {};
  const kind = { lock: "lock", burst: "sealed", action: "action" }[e.type] || e.severity || "info";
  const li = el("li", `item ${kind}`);
  const top = el("div", "item-top");
  top.append(el("span", `chip ${kind}`, { lock: "Locked", sealed: "Burst", action: "Response" }[kind] || kind), el("span", "inc", d.incident || ""), el("time", "", clock(e.ts)));
  li.append(top);
  if (e.type === "burst") {
    const files = d.files || [], n = files.length, where = fileName(d.folder);
    li.append(
      el("p", "what", n === 1 ? `Locked ${files[0]} in place` : n ? `Locked ${n} customer files in place` : `Burst in the ${where} folder`),
      el("p", "why", n ? `The customer data in ${where}/ stays where it was, locked. One command unlocks it.` : "No customer files in that folder needed locking."),
    );
  } else if (e.type === "action") {
    li.append(el("p", "what", ACTIONS[d.action]?.[2] || cap(d.action)), el("p", "who", `by ${e.actor || "someone"}`));
  } else if (e.type === "lock") {
    li.append(el("p", "what", lockText(e)), el("p", "who", who(e)));
  } else {
    li.append(el("p", "what", what(e)));
    const note = why(e);
    if (note) li.append(el("p", "why", note));
    li.append(el("p", "who", who(e)));
  }
  return li;
}

// incidents: triage card, report and respond buttons for each one

const unfolded = new Set();

function drawIncidents() {
  const box = $("incidents");
  const list = [...S.incidents.values()].filter((i) => i.alarms.length).sort((a, b) => b.alarms[0].ts - a.alarms[0].ts);
  const focus = document.activeElement?.dataset?.key;
  if (!list.length) {
    box.replaceChildren(el("p", "empty", "No incidents yet. When an alarm fires, its triage, report and response buttons show up here."));
    return;
  }
  box.replaceChildren(...list.map((inc, k) => (k ? folded(inc) : incidentCard(inc))));
  if (focus) box.querySelector(`[data-key="${CSS.escape(focus)}"]`)?.focus();
}

function incidentCard(inc) {
  const card = el("article", `incident${inc.dismissed ? " dismissed" : ""}`);
  const head = el("div", "inc-head");
  head.append(el("span", `chip ${inc.severity}`, inc.severity), el("strong", "", inc.id), el("span", "inc-state", stateOf(inc)));
  card.append(head, triage(inc), reportBlock(inc), respond(inc));
  if (inc.checklist) card.append(checklistCard(inc));
  return card;
}

function folded(inc) {
  const det = el("details", `incident${inc.dismissed ? " dismissed" : ""}`);
  det.open = unfolded.has(inc.id);
  det.addEventListener("toggle", () => (det.open ? unfolded.add(inc.id) : unfolded.delete(inc.id)));
  const title = inc.report?.title || what(inc.last || inc.alarms[0]);
  det.append(el("summary", "", `${inc.id} · ${title} · ${stateOf(inc)}`), triage(inc), reportBlock(inc), respond(inc));
  if (inc.checklist) det.append(checklistCard(inc));
  return det;
}

function stateOf(inc) {
  if (inc.dismissed) return "False alarm";
  if (inc.alarmAt != null && (inc.heldAt == null || inc.heldAt < inc.alarmAt)) return "Open";
  if (inc.heldAt != null) return "Contained";
  return "Logged";
}

function triage(inc) {
  const r = inc.report;
  const first = inc.alarms.find(serious) || inc.alarms[0];
  const box = el("div", "triage");
  const facts = el("dl", "facts");
  const add = (k, v, cls) => v && facts.append(el("dt", "", k), el("dd", cls || "", v));
  add("What happened", happened(inc));
  add("How fast", howFast(inc, first));
  const [pace, cls] = paceOf(inc);
  add("Script or person", pace, cls);
  add("Real data exposed", exposure(inc));
  add("Locked in place", inc.seals.map((x) => (x.files.length ? x.files.map((f) => `${x.folder}/${f}`).join(", ") : `${x.folder}/`)).join(", "));
  add("Next step", r ? nextStep(r.text) : "Waiting for the report.");
  add("Alerts sent", [...new Map(inc.notes.map((n) => [n.detail.channel, n.detail.status]))].map(([c, st]) => `${CHANNELS[c] || c} ${st}`).join(" · "));
  box.append(el("p", "triage-title", r?.source === "databricks" ? "AI triage" : "Triage"), facts);
  return box;
}

// the whole incident in one line, no per alarm speeds (the pace line has the peak)
function happened(inc) {
  const by = new Map();
  for (const a of inc.alarms) {
    const r = a.detail?.reason || "alarm";
    if (!by.has(r)) by.set(r, []);
    by.get(r).push(a);
  }
  const count = (n, one, many) => (n === 1 ? one : `${n} ${many}`);
  const parts = [...by].map(([r, list]) => {
    const n = list.length;
    if (r === "speed") return list.some((a) => S.procs.has(a.session)) ? "read files at machine speed" : "read at machine speed";
    if (r === "canary_touch") {
      // every canary read counts, not just the ones an alarm listed
      let k = 0;
      for (const sid of inc.sessions) k += S.sessions.get(sid)?.canaries || 0;
      k ||= new Set(list.flatMap((a) => a.detail.canary_ids || [])).size || n;
      return `touched ${count(k, "a canary customer", "canary customers")}`;
    }
    if (r === "canary_login") return `used ${count(n, "a canary login", "canary logins")}`;
    if (r === "unknown_account_login") return `tried ${count(n, "an account that doesn't exist", "accounts that don't exist")}`;
    if (r === "canary_contact") return `contacted ${count(n, "a canary customer", "canary customers")}`;
    if (r === "decoy_open") return `opened ${count(n, "a decoy file", "decoy files")}${list[0].file ? ` (${n > 1 ? "first " : ""}${fileName(list[0].file)})` : ""}`;
    return String(r).replaceAll("_", " ");
  });
  const text = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}` : parts[0];
  const exp = inc.alarms.find((a) => a.detail?.export_id)?.detail.export_id;
  return `${cap(text)}${exp ? ` from export ${exp}` : ""}.`;
}

// the breach notice checklist from a notify_customers action. drafted only, nothing gets sent
function checklistCard(inc) {
  const box = el("div", "triage");
  const facts = el("dl", "facts");
  for (const it of inc.checklist) {
    const item = it && typeof it === "object" ? it : { step: it };
    const due = item.due ?? item.by ?? item.date ?? item.deadline;
    facts.append(el("dt", "", due != null ? dateText(due) : "To do"), el("dd", "", String(item.step ?? item.text ?? item.task ?? item.title ?? "")));
  }
  box.append(el("p", "triage-title", "Breach notice checklist"), el("p", "empty", "Lab guidance, not legal advice"), facts);
  return box;
}

function dateText(v) {
  const d = typeof v === "number" ? new Date(v * 1000) : /^\d{4}-\d{2}-\d{2}$/.test(v) ? new Date(`${v}T12:00:00`) : new Date(v);
  return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

function howFast(inc, first) {
  const starts = [...inc.sessions].map((s) => S.firstRead.get(s) ?? S.first.get(s)).filter((t) => t != null);
  const start = starts.length ? Math.min(...starts) : first.ts;
  // an incident a drill step timed uses that step's number, same as the scoreboard
  const step = Object.keys(S.timed).find((p) => S.timed[p].inc === inc.id);
  const drilled = step ? stepTime(step) : null;
  let out = `Caught in ${drilled != null ? dur(drilled, false, true) : dur(first.ts - start)}`;
  if (inc.seals[0]) out += `, files locked ${later(inc.seals[0].ts - first.ts)}`;
  if (inc.firstHold) out += `, ${inc.firstHold.type === "lock" ? "locked" : "contained"} ${later(inc.firstHold.ts - first.ts)}`;
  return `${out}.`;
}

function paceOf(inc) {
  let rows = 0, files = 0;
  for (const a of inc.alarms) {
    const r = a.detail?.rate_per_min || 0;
    if (S.procs.has(a.session)) files = Math.max(files, r);
    else rows = Math.max(rows, r);
  }
  for (const s of inc.sessions) files = Math.max(files, S.procs.get(s)?.peak || 0);
  const speed = rows ? `peak ${fmt(rows)} rows a minute` : files ? `peak ${fmt(files)} files a minute` : "";
  const fast = rows > SPEED_ROWS_PER_MIN || files > SPEED_FILES_PER_MIN;
  const looks = inc.report?.looks_like || (speed ? (fast ? "ai_agent" : "person") : null);
  if (!looks) return [null];
  const agent = looks === "ai_agent";
  let text = agent ? "Likely a script or AI agent" : "Likely a person";
  if (speed && fast) text = agent ? "Machine speed: a script or AI agent" : "Machine speed. The report still says a person";
  if (speed && !fast) text = agent ? "Human speed. The report still says a script or AI agent" : "Human speed: likely a person";
  return [speed ? `${text} (${speed})` : text, agent ? "machine" : "human"];
}

function exposure(inc) {
  let rows = null, drive = false;
  const files = new Set();
  for (const sid of inc.sessions) {
    const s = S.sessions.get(sid);
    if (s) rows = (rows || 0) + Math.max(0, s.rows - s.canaries);
    const p = S.procs.get(sid);
    if (!p) continue;
    drive = true;
    for (const o of p.opens) {
      if (!o.sealed && S.folders.get(o.where)?.files.get(o.name)?.kind === "data") files.add(`${o.where}/${o.name}`);
    }
  }
  const out = [];
  if (rows != null) out.push(`${fmt(rows)} real customer ${rows === 1 ? "row" : "rows"}${inc.locked ? " before the lock" : " so far"}`);
  for (const sid of inc.sessions) {
    for (const c of S.copies.get(sid) || []) out.push(`${fmt(c.real)} real customer rows in honey locked export ${c.id}`);
  }
  if (drive && files.size) out.push(`${files.size} real customer ${files.size === 1 ? "file" : "files"}: ${[...files].join(", ")}`);
  else if (drive) out.push(inc.seals.length ? "None. The customer files were locked first" : "None so far");
  return out.length ? `${out.join(". ")}.` : null;
}

// the report's own next step, the sentence that starts with "Next"
function nextStep(text) {
  const parts = String(text || "").trim().split(/(?<=[.!?])\s+(?=[A-Z])/);
  const pick = parts.find((p) => /^next\b/i.test(p)) || parts.at(-1) || "";
  return cap(pick.replace(/^next[,:]?\s*/i, "")) || null;
}

function reportBlock(inc) {
  const r = inc.report;
  if (!r) return el("p", "empty", "The report is on its way.");
  const box = el("div", "report");
  const meta = el("div", "meta");
  const db = r.source === "databricks";
  meta.append(el("span", `chip ${db ? "src-databricks" : "src-template"}`, db ? "Databricks model" : "Template"), el("span", "", `Report · ${clock(r.ts)}`));
  box.append(meta, el("h3", "", r.title || "Incident report"), el("p", "", r.text || ""));
  return box;
}

// buttons live across redraws so a click mid attack still lands
const bars = new Map();
const sending = new Set();

function respond(inc) {
  let bar = bars.get(inc.id);
  if (!bar) {
    bar = el("div", "respond");
    for (const [action, [label]] of Object.entries(ACTIONS)) {
      const b = el("button", `act ${action}`, label);
      b.type = "button";
      b.dataset.key = `${inc.id}:${action}`;
      b.dataset.action = action;
      b.addEventListener("click", () => act(inc.id, action));
      bar.append(b);
    }
    bars.set(inc.id, bar);
  }
  const suggested = new Set(inc.report?.actions || []);
  for (const b of bar.children) {
    const action = b.dataset.action;
    const did = inc.actions.has(action) || (action === "lock" && inc.locked);
    const hint = suggested.has(action) && !did;
    b.textContent = ACTIONS[action][did ? 1 : 0];
    b.disabled = did || inc.dismissed || sending.has(b.dataset.key);
    b.classList.toggle("done", did);
    b.classList.toggle("suggested", hint);
    b.title = hint ? "The report suggests this" : "";
  }
  return bar;
}

function post(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (TOKEN) headers["X-Dyepack-Token"] = TOKEN;
  return fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
}

const refused = (r) => r.status === 401 || r.status === 403;
const TOKEN_HELP = "The server turned this down. Open the map with its control token link.";

async function act(id, action) {
  const e = { ts: S.now, type: "action", session: "dashboard", actor: "you", ip: "", severity: "info", detail: { incident: id, action } };
  if (REPLAY) return handle(e);
  const key = `${id}:${action}`;
  sending.add(key);
  dirty("incidents");
  try {
    const r = await post("/api/respond", { incident: id, action });
    if (refused(r)) throw new Error(TOKEN_HELP);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const back = await r.json().catch(() => ({}));
    const list = back?.checklist ?? back?.detail?.checklist;
    if (Array.isArray(list)) e.detail.checklist = list;
    handle(e);
  } catch (err) {
    toast(err.message === TOKEN_HELP ? TOKEN_HELP : "Couldn't reach the server. Nothing changed. Try again.");
  }
  sending.delete(key);
  dirty("incidents");
}

// the on-call phone shows the last few alerts

let phoneTop = null;

function drawPhone() {
  const when = new Date((S.now || Date.now() / 1000) * 1000);
  $("phone-time").textContent = when.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }).replace(/\s?[AP]M$/i, "");
  $("phone-date").textContent = when.toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
  const list = $("phone-notes");
  list.replaceChildren(...S.notes.slice(0, 3).map(noteCard));
  if (S.notes[0] && S.notes[0] !== phoneTop) list.firstChild.classList.add("new");
  phoneTop = S.notes[0] || null;
  $("phone-empty").hidden = S.notes.length > 0;
}

function noteCard(e) {
  const d = e.detail || {};
  const inc = S.incidents.get(d.incident);
  const a = inc?.alarms.filter((x) => x.ts <= e.ts).at(-1);
  const seal = inc?.seals.find((s) => s.ts <= e.ts);
  const sev = RANK[e.severity] > 0 ? e.severity : inc?.severity || "high";
  const li = el("li", `note ${d.channel} ${d.status}`);
  const top = el("div", "note-top");
  top.append(el("span", "app", { push: "Dyepack", sms: "Messages", email: "Mail", discord: "Discord" }[d.channel] || d.channel), el("time", "", clock(e.ts)));
  const body = d.summary || (a ? `${what(a)} · ${who(a)}.${seal ? ` Files in ${seal.folder}/ locked in place.` : ""}` : "Open the dashboard for details.");
  li.append(
    top,
    el("p", "note-title", d.title || `Dyepack ${sev} alarm ${d.incident}`),
    el("p", "note-body", body),
    el("p", "note-status", `${CHANNELS[d.channel] || d.channel} ${d.status}`),
  );
  return li;
}

// alert routes: which channels each severity goes to

let routes = structuredClone(ROUTES);

function buildRoutes() {
  const body = $("routes-body");
  for (const sev of Object.keys(ROUTES)) {
    const tr = el("tr");
    const th = el("th");
    th.scope = "row";
    th.append(el("span", `chip ${sev}`, sev));
    tr.append(th);
    for (const [ch, name] of Object.entries(CHANNELS)) {
      const td = el("td"), label = el("label", "switch"), box = el("input");
      box.type = "checkbox";
      box.dataset.route = `${sev}:${ch}`;
      box.setAttribute("aria-label", `${cap(sev)} alarms by ${name}`);
      box.addEventListener("change", () => saveRoute(box));
      label.append(box, el("span"));
      td.append(label);
      tr.append(td);
    }
    body.append(tr);
  }
}

function drawRoutes() {
  for (const box of document.querySelectorAll("[data-route]")) {
    const [sev, ch] = box.dataset.route.split(":");
    box.checked = Array.isArray(routes[sev]) && routes[sev].includes(ch);
  }
}

async function loadRoutes() {
  const note = $("routes-note");
  if (REPLAY) {
    note.textContent = "In the replay, changes stay on this page.";
    return drawRoutes();
  }
  try {
    const r = await fetch("/api/alert-routes");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const got = await r.json();
    if (!got || typeof got !== "object" || Array.isArray(got)) throw new Error("bad routes");
    routes = { ...structuredClone(ROUTES), ...got };
    note.textContent = "Loaded from the server. Changes save right away.";
  } catch {
    note.textContent = "Couldn't load the saved routes. Showing the defaults.";
  }
  drawRoutes();
}

async function saveRoute(box) {
  const [sev, ch] = box.dataset.route.split(":");
  const before = structuredClone(routes);
  const on = new Set(routes[sev] || []);
  if (box.checked) on.add(ch);
  else on.delete(ch);
  routes[sev] = Object.keys(CHANNELS).filter((c) => on.has(c));
  if (REPLAY) return;
  try {
    const r = await post("/api/alert-routes", routes);
    if (refused(r)) throw new Error(TOKEN_HELP);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    $("routes-note").textContent = "Saved.";
  } catch (err) {
    routes = before;
    drawRoutes();
    toast(err.message === TOKEN_HELP ? TOKEN_HELP : "Couldn't save the alert routes. Is the server running?");
  }
}

let toastTimer = 0;
function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 4000);
}

// scoreboard

const stepTime = (phase) => S.timed[phase]?.drill ?? S.timed[phase]?.live ?? null;

function scoreValue(key) {
  // the triage card reads the same numbers, which keeps the two in step
  if (key === "detect_seconds") return stepTime("heist-1");
  if (key === "rows_exposed" && S.live.firstRead != null) return S.live.exposed;
  if (S.score[key] != null) return S.score[key];
  if (key === "normal_alarms" && S.phases.normal) return S.live.normalAlarms;
  return null;
}

function tileText(key, v) {
  switch (key) {
    case "normal_alarms":
      return [fmt(v), "Goal: 0", v > 0 ? "fail" : S.phases.normal === "end" ? "pass" : ""];
    case "detect_seconds":
      return [dur(v, true, true), "Goal: 10 s or less", v <= 10 ? "pass" : "fail"];
    case "rows_exposed":
      return [fmt(v), `${((100 * v) / TABLE_ROWS).toFixed(1)}% of the table before the lock`, ""];
    case "guesses_cracked":
      return [fmt(v), "The thief can't tell which list is real", ""];
    case "ai_pick": {
      // pick and real come in counted from 0
      if (typeof v !== "object") return [String(v), "", ""];
      const of = v.lists ? ` of ${v.lists}` : "";
      if (v.pick == null) return ["No answer", "No model gave a pick this run", ""];
      if (v.real == null) return [`List ${v.pick + 1}`, `Its pick${of}`, ""];
      if (v.pick === v.real) return ["Yes", `Lucky guess: a 1 in ${v.lists || "?"} chance`, "fail"];
      return ["No", `It picked list ${v.pick + 1}. The real one was list ${v.real + 1}${of}.`, "pass"];
    }
  }
  return [String(v), "", ""];
}

function drawScore() {
  for (const tile of document.querySelectorAll(".tile")) {
    const key = tile.id.slice(2);
    const v = scoreValue(key);
    const [value, note, verdict] = v == null ? ["Not yet", tile.dataset.note, ""] : tileText(key, v);
    const big = tile.querySelector(".v");
    if (v != null && big.classList.contains("wait")) retrigger(tile, "pop");
    big.textContent = value;
    big.classList.toggle("wait", v == null);
    tile.querySelector(".n").textContent = note;
    tile.dataset.verdict = verdict;
  }
}

function drawPrints() {
  const items = [...S.exports].reverse().map(([id, x]) => {
    const li = el("li", x.hits ? "print leaked" : "print");
    const top = el("div", "print-top");
    top.append(el("strong", "", id), el("span", `chip ${x.hits ? "leaked" : "clean"}`, x.hits ? "Leaked" : "No use seen"));
    li.append(top, el("p", "", `${fmt(x.rows || 0)} rows with ${fmt(x.canaries || 0)} canaries of its own`), el("p", "who", `Made by ${x.actor} at ${clock(x.ts)}`));
    if (x.hits) li.append(el("p", "trace", `${x.hits} ${x.hits === 1 ? "alarm points" : "alarms point"} to this copy`));
    return li;
  });
  $("prints").replaceChildren(...items);
  $("prints-empty").hidden = S.exports.size > 0;
}

// feeds

const CONN = { connecting: "Connecting", live: "Live", retry: "Reconnecting", down: "Not connected", replay: "Replay" };

function setConn(state) {
  const c = $("conn");
  c.dataset.state = state;
  c.textContent = CONN[state];
  $("conn-note").hidden = state !== "retry" && state !== "down";
}

function live() {
  setConn("connecting");
  const es = new EventSource("/events");
  es.onopen = () => setConn("live");
  es.onerror = () => setConn(es.readyState === EventSource.CLOSED ? "down" : "retry");
  es.onmessage = (m) => {
    let e;
    try {
      e = JSON.parse(m.data);
    } catch {
      return;
    }
    if (e && e.type) handle(e);
  };
}

async function replay() {
  setConn("replay");
  $("player").hidden = false;
  let events = [];
  try {
    events = await (await fetch("sample_events.json")).json();
  } catch {
    $("clock").textContent = "Couldn't load the recording";
    return;
  }
  if (!events.length) return;
  // "at" is when an event plays in replay seconds. quiet stretches go faster, ts stays real
  const t0 = Math.min(...events.map((e) => e.ts));
  const when = (e) => e.at ?? e.ts - t0;
  events.sort((a, b) => when(a) - when(b));
  const total = when(events.at(-1));
  const play = $("play");
  let i = 0, at = 0, speed = 1, playing = true, last = performance.now();
  const label = () => (play.textContent = i >= events.length ? "Play again" : playing ? "Pause" : "Play");
  const restart = () => {
    fresh();
    i = 0;
    at = 0;
    playing = true;
    dirty(...ALL);
  };
  play.onclick = () => {
    if (i >= events.length) restart();
    else playing = !playing;
    label();
  };
  $("restart").onclick = () => {
    restart();
    label();
  };
  for (const b of document.querySelectorAll("[data-speed]")) {
    b.onclick = () => {
      speed = Number(b.dataset.speed);
      for (const o of document.querySelectorAll("[data-speed]")) o.setAttribute("aria-pressed", String(o === b));
    };
  }
  setInterval(() => {
    const now = performance.now();
    if (playing) at = Math.min(total, at + ((now - last) / 1000) * speed);
    last = now;
    while (i < events.length && when(events[i]) <= at) handle(events[i++]);
    if (i >= events.length && playing) {
      playing = false;
      label();
    }
    $("clock").textContent = `${mmss(at)} / ${mmss(total)}`;
  }, 100);
  label();
}

fresh();
for (const t of document.querySelectorAll(".tile")) t.dataset.note = t.querySelector(".n").textContent;
buildRoutes();
loadRoutes();
let resizing = 0;
const ro = new ResizeObserver(() => {
  clearTimeout(resizing);
  resizing = setTimeout(() => {
    layoutMine();
    drawChart();
    drawDrive();
  }, 60);
});
for (const id of ["mine", "chart", "drive"]) ro.observe($(id));
dirty(...ALL);
if (REPLAY) replay();
else live();
