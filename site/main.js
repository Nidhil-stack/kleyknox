// KleyKnox site: the file switcher, battlement edges, the passphrase probe, and the motion layer.
// Everything works without this script; it only adds the switcher, the probe and the movement.

const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ---------- 2. what is on the stick ---------- */
const FILES = [
  {
    name: "personale.age", size: "581 byte",
    body: "age-encryption.org/v1\n-> scrypt iY2iEM6ALAVPbQ84Ro0AkA 20\nnW1Lq0b2kR9x3cXvT6pYQ8hZ0fJmA4sDk7GuEo5wIr\n--- 4bWq0tYk2mPz8xXc1vN6sJ3dL9hR5fQ0gA7eKuYo\n7c 2f 91 e4 0b a8 55 3d c1 9e 6f 02 b7 48 d3 1a\ne0 64 af 13 78 c2 5b 9d 04 f6 21 8e 37 ca 90 5e\nb1 0d 6a f3 82 47 ec 19 5f a0 3b d8 76 2c e9 41",
    fact: 'La chiave SSH, cifrata con scrypt a 2<sup>20</sup>. Si apre anche senza KleyKnox: <code>age -d personale.age</code>.',
  },
  {
    name: "personale.pub", size: "95 byte",
    body: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcU1xqZph7w1y4kmFf9Ey6UV7s2X8xcQsB7u88ttT+H kleyknox:personale",
    fact: "La chiave pubblica SSH, in chiaro: è quella che metti nei server, in <code>authorized_keys</code>.",
  },
  {
    name: "mail.gpg.age", size: "1,1 KB",
    body: "age-encryption.org/v1\n-> scrypt Qm8dXz1kP0aW7cRt4yLb2A 20\nT3vHq9mZx0bK1cWd8eYf2gRn4hSj6iUk7oLp5aMs9uB\n--- Zk2Pq8wR1tYx4vN7mB0cL3dF6gH9jS5aE2uIo8kT\n3a 9f 0c e7 52 b8 14 d6 6e 01 c9 a4 3b 77 f2 08\n5d c3 2e 90 18 af 64 bb 07 e1 4c 39 d2 86 0f 7a",
    fact: "La chiave GPG insieme alla sua passphrase GPG, casuale: la conosce solo la chiavetta.",
  },
  {
    name: "mail.asc", size: "653 byte",
    body: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZxx6cBYJKwYBBAHaRw8BAQdA9Qf0dS3mWkH2pZ8\ntLvB6cR1yX4nE7aK0uJ5oP3iT2gbtCRQcm92YSBLbGV5\nS25veCA8cHJvdmFAZXhhbXBsZS5vcmc+iJMEExYKADsW\n=kLyK\n-----END PGP PUBLIC KEY BLOCK-----",
    fact: "La chiave pubblica GPG, da dare a chi deve scriverti cifrato.",
  },
];
const FILES_EN = [
  {
    name: "personal.age", size: "581 bytes",
    body: "age-encryption.org/v1\n-> scrypt iY2iEM6ALAVPbQ84Ro0AkA 20\nnW1Lq0b2kR9x3cXvT6pYQ8hZ0fJmA4sDk7GuEo5wIr\n--- 4bWq0tYk2mPz8xXc1vN6sJ3dL9hR5fQ0gA7eKuYo\n7c 2f 91 e4 0b a8 55 3d c1 9e 6f 02 b7 48 d3 1a\ne0 64 af 13 78 c2 5b 9d 04 f6 21 8e 37 ca 90 5e\nb1 0d 6a f3 82 47 ec 19 5f a0 3b d8 76 2c e9 41",
    fact: 'The SSH key, encrypted with scrypt at 2<sup>20</sup>. It opens without KleyKnox too: <code>age -d personal.age</code>.',
  },
  {
    name: "personal.pub", size: "95 bytes",
    body: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcU1xqZph7w1y4kmFf9Ey6UV7s2X8xcQsB7u88ttT+H kleyknox:personal",
    fact: "The public SSH key, in the clear: the one you put on servers, in <code>authorized_keys</code>.",
  },
  {
    name: "mail.gpg.age", size: "1.1 KB",
    body: "age-encryption.org/v1\n-> scrypt Qm8dXz1kP0aW7cRt4yLb2A 20\nT3vHq9mZx0bK1cWd8eYf2gRn4hSj6iUk7oLp5aMs9uB\n--- Zk2Pq8wR1tYx4vN7mB0cL3dF6gH9jS5aE2uIo8kT\n3a 9f 0c e7 52 b8 14 d6 6e 01 c9 a4 3b 77 f2 08\n5d c3 2e 90 18 af 64 bb 07 e1 4c 39 d2 86 0f 7a",
    fact: "The GPG key together with its random GPG passphrase: only the stick knows it.",
  },
  {
    name: "mail.asc", size: "653 bytes",
    body: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZxx6cBYJKwYBBAHaRw8BAQdA9Qf0dS3mWkH2pZ8\ntLvB6cR1yX4nE7aK0uJ5oP3iT2gbtCRQcm92YSBLbGV5\nS25veCA8cHJvdmFAZXhhbXBsZS5vcmc+iJMEExYKADsW\n=kLyK\n-----END PGP PUBLIC KEY BLOCK-----",
    fact: "The public GPG key, for whoever needs to write to you encrypted.",
  },
];
const EN = document.documentElement.lang === "en";
const SHOWN = EN ? FILES_EN : FILES;

const tabs = [...document.querySelectorAll(".files [role=tab]")];
const fileBox = document.querySelector(".file");
const show = (i) => {
  const f = SHOWN[i];
  tabs.forEach((t, j) => t.setAttribute("aria-selected", String(j === i)));
  const swap = () => {
    document.getElementById("file-name").textContent = f.name;
    document.getElementById("file-size").textContent = f.size;
    document.getElementById("file-body").textContent = f.body;
    document.getElementById("file-fact").innerHTML = f.fact;
    fileBox.classList.remove("is-swapping");
  };
  if (reduce) return swap();
  fileBox.classList.add("is-swapping");
  setTimeout(swap, 300);
};
tabs.forEach((t, i) => {
  t.addEventListener("click", () => show(i));
  t.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    e.preventDefault();
    const next = (i + (e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus();
    show(next);
  });
});

/* ---------- battlement edges: the tower's top, cut into pictures and the command sheet ---------- */
const merlon = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--merlon")) || 28;
const crenels = (w, h, m, top) => {
  // Points along one edge: up for a merlon, down for a gap, edge to edge.
  const pts = [];
  const n = Math.max(3, Math.round(w / (m * 2)) | 1); // odd count, so both ends are merlons
  const step = w / n;
  for (let i = 0; i < n; i++) {
    const x0 = i * step, x1 = (i + 1) * step;
    const y = i % 2 === 0 ? 0 : m;
    if (top) pts.push(`${x0}px ${y}px`, `${x1}px ${y}px`);
    else pts.push(`${w - x0}px ${h - y}px`, `${w - x1}px ${h - y}px`);
  }
  return pts;
};
const battle = () => {
  const m = merlon();
  document.querySelectorAll(".battlement > .frame, .probe-film video").forEach((img) => {
    const { width: w, height: h } = img.getBoundingClientRect();
    if (!w) return;
    img.style.setProperty("--battle", `polygon(${[...crenels(w, h, m, true), `${w}px ${h}px`, `0 ${h}px`].join(", ")})`);
  });
  document.querySelectorAll(".battlement-both").forEach((el) => {
    const { width: w, height: h } = el.getBoundingClientRect();
    if (!w) return;
    el.style.setProperty("--battle", `polygon(${[...crenels(w, h, m, true), ...crenels(w, h, m, false)].join(", ")})`);
  });
};
battle();
addEventListener("resize", battle);
addEventListener("load", battle);

/* ---------- 8. the probe: how long the passphrase holds against scrypt 2^20 ---------- */
const RATE = 10_000; // guesses per second, a hundred GPUs against scrypt N=2^20 (stated on the page)
const MIN = 12;      // kleyknox refuses anything shorter
const bitsOf = (p) => {
  const words = p.trim().split(/[\s\-_.]+/).filter(Boolean);
  // Several words: count them as picked at random from a 7,776-word list (Diceware).
  if (words.length >= 4 && words.every((w) => /^\p{L}+$/u.test(w) && w.length >= 3)) return words.length * Math.log2(7776);
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^A-Za-z0-9]/.test(p)) pool += 33;
  // Repeats and runs make a string far weaker than its length says: count distinct characters only.
  const distinct = new Set(p).size;
  return Math.min(p.length, distinct + (p.length - distinct) * 0.25) * Math.log2(pool || 1);
};
const WORDS = EN
  ? { lt1: "less than a second", min: "minutes", h: "hours", d: "days", y: "years", ky: "thousand years", my: "million years", inf: "longer than the age of the universe" }
  : { lt1: "meno di un secondo", min: "minuti", h: "ore", d: "giorni", y: "anni", ky: "mila anni", my: "milioni di anni", inf: "più dell'età dell'universo" };
const span = (s) => {
  const year = 3600 * 24 * 365;
  if (s < 1) return WORDS.lt1;
  if (s < 3600) return `${Math.ceil(s / 60)} ${WORDS.min}`;
  if (s < 86400) return `${Math.round(s / 3600)} ${WORDS.h}`;
  if (s < year) return `${Math.round(s / 86400)} ${WORDS.d}`;
  const y = s / year;
  if (y < 1e3) return `${Math.round(y)} ${WORDS.y}`;
  if (y < 1e6) return `${Math.round(y / 1e3)} ${WORDS.ky}`;
  if (y < 1e9) return `${Math.round(y / 1e6)} ${WORDS.my}`;
  return WORDS.inf;
};
const probe = document.getElementById("probe");
const field = document.getElementById("probe-input");
const out = document.getElementById("probe-result");
const measure = () => {
  const p = field.value;
  if (!p) { out.textContent = EN ? "Type a passphrase: this page does the maths and sends it nowhere." : "Scrivi una passphrase: il conto lo fa questa pagina, e non la invia a nessuno."; return; }
  const bits = bitsOf(p);
  const half = Math.pow(2, bits - 1) / RATE; // on average the right guess comes half way
  const short = p.length < MIN;
  const verdict = `class="${half > 3.15e9 ? "good" : "bad"}"`;
  out.innerHTML = EN
    ? `About <strong>${Math.round(bits)} bits</strong>: on average it would take <strong ${verdict}>${span(half)}</strong>.` +
      (short ? ` <span class="bad">KleyKnox would refuse it: ${p.length} characters, at least ${MIN} needed.</span>` : "")
    : `Circa <strong>${Math.round(bits)} bit</strong>: in media servirebbero <strong ${verdict}>${span(half)}</strong>.` +
      (short ? ` <span class="bad">KleyKnox la rifiuterebbe: ha ${p.length} caratteri, ne servono almeno ${MIN}.</span>` : "");
};
probe.addEventListener("submit", (e) => { e.preventDefault(); measure(); });
field.addEventListener("input", measure);

/* ---------- motion: entrances, the shutter, one drifting picture ---------- */
if (!reduce && "IntersectionObserver" in window) {
  const parts = [
    ".showcase-list h2", ".files li", ".showcase-fact",
    ".field h2", ".field .card", ".field .clause",
    ".board .tile",
    ".name h2", ".name-copy > p", ".name-keys", ".name-picture",
    ".speaks .mark",
    ".sheet",
    ".probe h2", ".probe-film", ".probe-sentence", ".probe-result", ".probe-note",
    ".foot .blocks span", ".foot-grid > *",
  ];
  const groups = new Map();
  document.querySelectorAll(parts.join(",")).forEach((el) => {
    const section = el.closest("section, footer");
    const n = groups.get(section) || 0;
    groups.set(section, n + 1);
    el.dataset.rise = "";
    el.style.setProperty("--i", String(Math.min(n, 8)));
  });
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      e.target.classList.add("is-in");
      io.unobserve(e.target);
    });
  }, { rootMargin: "0px 0px -12% 0px" });
  document.querySelectorAll("[data-rise], .shutter").forEach((el) => io.observe(el));

  // The vault photograph drifts slowly as the panel passes.
  const drift = document.querySelector(".drift");
  const tick = () => {
    const r = drift.getBoundingClientRect();
    const p = Math.max(-1, Math.min(1, (r.top + r.height / 2 - innerHeight / 2) / innerHeight));
    drift.style.transform = `scale(1.08) translateY(${(p * 3).toFixed(2)}%)`;
  };
  addEventListener("scroll", () => requestAnimationFrame(tick), { passive: true });
  tick();
} else {
  document.querySelectorAll(".shutter").forEach((el) => el.classList.add("is-in"));
}

/* The clip plays only while it is on screen, and never under reduced motion. */
const film = document.querySelector(".probe-film video");
if (film) {
  if (reduce) { film.removeAttribute("autoplay"); film.pause(); }
  else if ("IntersectionObserver" in window) {
    new IntersectionObserver(([e]) => (e.isIntersecting ? film.play().catch(() => {}) : film.pause())).observe(film);
  }
}
