"use strict";

const byId = id => document.getElementById(id);
const token = document.querySelector('meta[name="neighbor-token"]').content;
let state;
let selected;
let activeTab = "diff";
let view = "reviews";
let codePath = "";
let codeAnchor = "";
const openFolders = new Set();
const treeEntries = new Map();
let treeHead;
let treeScroll = 0;
let selectedCommit;
let screenVersion = 0;
let latestState = 0;
const views = { code: "Code", history: "History", branches: "Branches", reviews: "Reviews",
  peers: "Peers", settings: "Settings", clone: "Clone repository" };
let diffVersion = 0;
let requestedComment;
let busy = false;
const seenNotices = new Set();
const desktopAlerts = byId("desktop-alerts");
let nearbyPolling = false;
let nearbyPeer;
let displayedStorage;
let fileThemeRequest;

const logo = byId("repo-mark");
if (logo?.dataset.png && typeof createImageBitmap === "function") {
  const bytes = assetBytes(logo.dataset.png);
  createImageBitmap(new Blob([bytes], { type: "image/png" })).then(bitmap => {
    logo.getContext("2d").drawImage(bitmap, 0, 0);
    bitmap.close();
    logo.classList.add("mark-loaded");
  }).catch(() => {});
}

function assetBytes(base64) {
  return Uint8Array.from(atob(base64), char => char.charCodeAt(0));
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function button(text, action, className) {
  const node = element("button", text, className);
  node.type = "button";
  node.addEventListener("click", action);
  return node;
}

async function api(path, body) {
  const headers = { "X-Neighbor-Token": token };
  if (body && !(body instanceof Blob)) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const response = await fetch("/api/" + path, {
    headers, method: body === undefined ? "GET" : "POST", body,
  });
  if (!response.ok) throw new Error((await response.json()).error);
  return path === "export" ? response.blob() : response.json();
}

function notify(text, error = false, reviewId) {
  const node = byId("notice");
  byId("notice-text").textContent = text;
  const action = byId("notice-action");
  action.hidden = !reviewId;
  action.onclick = reviewId ? () => {
    openReviewDetails(reviewId);
    notify("");
  } : null;
  node.classList.toggle("error", error);
  node.hidden = !text;
  if (error) {
    const dialog = document.querySelector("dialog[open]");
    if (dialog) {
      let alert = dialog.querySelector(".dialog-error");
      if (!alert) {
        alert = element("p", "", "help dialog-error");
        alert.setAttribute("role", "alert");
        dialog.append(alert);
      }
      alert.textContent = text;
    }
  }
}

async function refresh() {
  const version = ++latestState;
  const previous = state;
  const next = await api("state");
  if (version !== latestState) return;
  state = next;
  for (const key of ["branches", "shared", "branch_status"]) Object.setPrototypeOf(state[key], null);
  if (state.bootstrap && !["clone", "peers", "settings"].includes(view)) view = "clone";
  if (previous?.bootstrap && !state.bootstrap) view = "code";
  if (previous?.repo !== state.repo) {
    codePath = "";
    codeAnchor = "";
    openFolders.clear();
    treeEntries.clear();
    treeHead = undefined;
    treeScroll = 0;
    selectedCommit = undefined;
  }
  if (!previous) setupTeam();
  const viewed = previous?.proposals.find(review => review.id === selected);
  if (viewed && !viewed.superseded && state.proposals.some(review => review.id === selected && review.superseded)) {
    const latest = state.proposals.find(review => !review.superseded && review.who === viewed.who &&
      review.source === viewed.source && review.target === viewed.target);
    if (latest) selected = latest.id;
  }
  if (!state.proposals.some(proposal => proposal.id === selected)) {
    selected = state.proposals[0]?.id;
  }
  render();
}

// A refresh rebuilds review panels, so wait until typed comments are sent or cleared.
function unsentComment() {
  return [...document.querySelectorAll(".comment-form textarea, .inline-editor textarea")]
    .some(field => field.value.trim());
}

async function checkNearby() {
  if (nearbyPolling) return;
  nearbyPolling = true;
  try {
    const { enabled, error, notices, peer, version } = await api("nearby");
    const previousPeer = nearbyPeer;
    nearbyPeer = peer;
    updatePairingCode();
    renderPeerPresence();
    desktopAlerts.hidden = (!enabled && !peer.enabled) || typeof Notification === "undefined" || Notification.permission !== "default";
    const status = byId("nearby-status");
    const rows = notices.map(notice => {
      const message = notice.name + " submitted a branch for review. Import their exchange to open it.";
      if (state?.notifications?.reviews && !seenNotices.has(notice.id)) desktopNotification(message, notice.id);
      seenNotices.add(notice.id);
      return element("p", message);
    });
    if (peer.enabled) {
      const nearby = peer.online.length ? "Connected recently · " + peer.online.join(", ")
        : "Looking for paired teammates on nearby Wi-Fi.";
      rows.unshift(element("p", peer.starting ? "Starting nearby Wi-Fi…" : (peer.error || nearby)));
      for (const activity of peer.activity) rows.push(element("p", activity));
    } else {
      if (error) rows.unshift(element("p", "LAN alerts unavailable. " + error));
      if (!rows.length) rows.push(element("p", enabled ? "Listening for reviews from trusted teammates on the LAN."
        : "Nearby Wi-Fi is off. Start PeerTree with nearby Wi-Fi enabled to sync directly."));
    }
    if (state && version !== state.version && !busy &&
        !document.querySelector("dialog[open]") && !document.activeElement?.matches("input,textarea,select") &&
        !unsentComment()) {
      const previous = state;
      await refresh();
      announceChanges(previous);
    }
    if (state?.notifications?.peers && previousPeer?.enabled && peer.enabled) {
      const before = previousPeer.reachable || [];
      const after = peer.reachable || [];
      const joined = after.filter(id => !before.includes(id)).map(name);
      const left = before.filter(id => !after.includes(id)).map(name);
      const messages = [];
      if (joined.length) messages.push(joined.join(", ") + (joined.length === 1 ? " is" : " are") + " nearby.");
      if (left.length) messages.push(left.join(", ") + (left.length === 1 ? " is" : " are") + " out of range.");
      if (messages.length) {
        desktopNotification(messages.join(" "), "nearby-peers");
        if (!busy && byId("notice").hidden && !document.querySelector("dialog[open]")) notify(messages.join(" "));
      }
    }
    if (status.textContent !== rows.map(row => row.textContent).join("")) status.replaceChildren(...rows);
    if (view === "settings" && peer.enabled) await refreshStorage(screenVersion);
  } catch {
    // The next poll retries after a temporary connection error.
  } finally {
    nearbyPolling = false;
  }
}

function desktopNotification(text, tag) {
  if (window.Notification?.permission !== "granted") return;
  try { new Notification("PeerTree", { body: text, tag }); }
  catch { /* The in-app notices still work when the WebView cannot show notifications. */ }
}

function announceChanges(previous) {
  if (!previous || state.bootstrap) return;
  const preferences = state.notifications || {};
  const known = new Map(previous.proposals.map(item => [item.id, item]));
  const alerts = [];
  for (const review of state.proposals) {
    const old = known.get(review.id);
    if (preferences.reviews && !old && review.who !== state.me && !review.superseded && !review.merged) {
      alerts.push({ text: name(review.who) + " submitted “" + review.title + "” for review.", id: review.id });
    }
    if (preferences.decisions && old && review.who === state.me) {
      for (const vote of review.reviews) {
        const prior = old.reviews.find(item => item.who === vote.who);
        if (prior && prior.at === vote.at && prior.vote === vote.vote && prior.note === vote.note) continue;
        const action = vote.vote === "approve" ? " approved " : " requested changes on ";
        alerts.push({ text: name(vote.who) + action + "“" + review.title + "”.", id: review.id });
      }
    }
  }
  const diverged = Object.keys(state.branch_status).filter(branch =>
    state.branch_status[branch] === "diverged" && previous.branch_status[branch] !== "diverged");
  if (preferences.diverge && diverged.length) {
    alerts.push({ text: diverged.join(", ") + " diverged from the published branch tips." });
  }
  for (const alert of alerts) desktopNotification(alert.text, alert.id || "branch-divergence");
  if (alerts.length) notify(alerts[0].text, false, alerts[0].id);
}

desktopAlerts.addEventListener("click", async () => {
  await Notification.requestPermission();
  await checkNearby();
});

async function perform(action, waiting) {
  if (busy) return;
  busy = true;
  notify(waiting || "");
  const active = document.activeElement;
  if (active?.tagName === "BUTTON") active.disabled = true;
  try {
    return await action();
  } catch (error) {
    notify(error.message, true);
  } finally {
    if (active?.tagName === "BUTTON") active.disabled = false;
    busy = false;
  }
}

function change(path, input, onSuccess, waiting) {
  return perform(async () => {
    const previous = state;
    const result = await api(path, input);
    if (result.selected) {
      view = "reviews";
      selected = result.selected;
      activeTab = "diff";
    }
    if (onSuccess) onSuccess();
    await refresh();
    if (["import", "refresh", "team"].includes(path)) await checkNearby();
    notify(result.message || (path === "check"
      ? (result.passed ? "Pipeline passed." : "Pipeline failed. Review the output below.")
      : (nearbyPeer?.enabled ? "Branch submitted. Paired teammates receive it when nearby."
        : "Branch submitted for review. Export an exchange to share it.")));
    if (["import", "refresh", "team"].includes(path)) announceChanges(previous);
    return result;
  }, waiting);
}

function status(proposal) {
  if (proposal.merged) return ["Merged", "ok"];
  if (proposal.superseded) return ["Superseded", ""];
  if (proposal.quorum_stale) return ["Rebase needed", "alert"];
  if (proposal.blocked) return ["Changes requested", "alert"];
  if (proposal.ready) return ["Ready to merge", "ok"];
  return ["In review", ""];
}

function pill(text, style = "") {
  return element("span", text, "pill " + style);
}

function name(id) {
  return state.people[id] || id.slice(0, 12);
}

function navigate(screen) {
  if (!state || (state.bootstrap && !["clone", "peers", "settings"].includes(screen))) return;
  if (screen === "settings") setupTeam();
  view = screen;
  render();
}

function render() {
  const version = ++screenVersion;
  const worktree = state.worktrees.find(item => item.path === state.repo);
  const openReviews = state.proposals.filter(item => !item.merged && !item.superseded);
  const open = openReviews.length;
  const requirements = new Set(openReviews.filter(item => !item.policy_error).map(item => item.required));
  const required = requirements.size === 1 ? [...requirements][0] : 0;
  const diverged = Object.keys(state.branch_status).filter(branch => state.branch_status[branch] === "diverged");
  byId("project").textContent = state.project;
  byId("repo-caption").textContent = state.bootstrap ? "Initial checkout"
    : displayedStorage ? "Local replica · " + formatBytes(displayedStorage.repository) : "Local repository";
  byId("page-title").textContent = views[view];
  byId("page-subtitle").textContent = {
    code: "Browse the committed files in the selected worktree",
    history: "Recent commits in the selected worktree",
    branches: "Compare local branches with signed branch tips",
    reviews: open + " open" + (required ? " · " + required + (required === 1 ? " approval" : " approvals") + " to merge" : ""),
    peers: "Trusted identities and recent sync activity",
    settings: "This Mac · " + name(state.me),
    clone: state.project,
  }[view];
  for (const section of document.querySelectorAll("[data-screen]")) section.hidden = section.dataset.screen !== view;
  for (const item of document.querySelectorAll("[data-view]")) {
    const target = item.dataset.view;
    item.hidden = state.bootstrap ? !["clone", "peers", "settings"].includes(target) : target === "clone";
    if (target === view) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  byId("worktree-picker").hidden = state.bootstrap;
  const select = byId("worktree");
  options(select, state.worktrees.map(({ path, branch }) =>
    [path, (branch || "detached HEAD") + (state.worktrees.length > 1 ? " · " + path.split("/").at(-1) : "")]), state.repo);
  select.title = worktree?.path || state.repo;
  select.disabled = state.worktrees.length < 2;
  byId("count").textContent = open;
  byId("count").hidden = !open;
  byId("branch-count").textContent = diverged.length;
  byId("branch-count").hidden = !diverged.length;
  byId("divergence").hidden = state.bootstrap || !diverged.length;
  byId("divergence-text").textContent = diverged.join(", ") +
    (diverged.length === 1 ? " has" : " have") + " diverged from the published branch tips.";
  renderPeerPresence();
  if (view === "clone") renderClone();
  if (view === "reviews") renderReviews();
  if (view === "branches") renderBranches();
  if (view === "code") {
    loadScreen(Promise.all([loadCodeWorkspace(), loadFileTheme()]), "code", version,
      (node, [workspace, theme]) => renderCode(node, workspace, theme));
  }
  if (view === "history") loadScreen(api("history"), "history", version, renderHistory);
  if (view === "peers") loadScreen(api("activity"), "activity", version, renderActivity);
  if (view === "settings") {
    renderQuorumSettings();
    byId("workspace-path").textContent = state.repo;
    byId("tracking-status").textContent = state.tracking_error ? "Tracking error: " + state.tracking_error
      : "Sync now refreshes signed tips under team/ without changing your checked-out branch.";
    byId("protected-branches").textContent = "Protected branches: " + state.protected.join(", ");
    byId("pipeline-settings").hidden = state.bootstrap;
    for (const toggle of document.querySelectorAll("[data-notification]")) {
      toggle.checked = !!state.notifications?.[toggle.dataset.notification];
    }
    refreshStorage(version);
  }
}

function formatBytes(bytes) {
  if (bytes < 1000) return bytes + " B";
  const units = ["KB", "MB", "GB", "TB"];
  const power = Math.min(units.length, Math.floor(Math.log10(bytes) / 3));
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(bytes / 1000 ** power)
    + " " + units[power - 1];
}

async function refreshStorage(version) {
  try {
    const storage = await api("storage");
    if (version !== screenVersion) return;
    displayedStorage = storage;
    const keys = ["repository", "cache", "pending"];
    const total = keys.reduce((sum, key) => sum + storage[key], 0);
    for (const key of keys) {
      byId("storage-" + key).textContent = formatBytes(storage[key]);
      byId("bar-" + key).style.flexGrow = total ? storage[key] / total : 0;
    }
    byId("storage-path").textContent = storage.path;
    byId("prune-cache").disabled = !storage.can_prune;
    byId("storage-error").hidden = true;
    if (!state.bootstrap) byId("repo-caption").textContent = "Local replica · " + formatBytes(storage.repository);
  } catch (error) {
    if (version !== screenVersion) return;
    byId("storage-error").textContent = error.message;
    byId("storage-error").hidden = false;
  }
}

function loadScreen(request, id, version, renderRows) {
  const node = byId(id);
  if (id !== "code" || !node.querySelector(".code-layout")) {
    node.replaceChildren(element("p", "Loading…", "help empty-list"));
  }
  request.then(data => {
    if (version === screenVersion) renderRows(node, data);
  }).catch(error => {
    if (version === screenVersion) node.replaceChildren(element("p", error.message, "help empty-list"));
  });
}

function goToPath(path, anchor = "") {
  codePath = path;
  codeAnchor = anchor;
  const parts = path.split("/");
  for (let end = 1; end < parts.length; end++) openFolders.add(parts.slice(0, end).join("/"));
  navigate("code");
}

function loadFileTheme() {
  fileThemeRequest ??= (async () => {
    const embedded = byId("embedded-file-icons")?.textContent;
    if (embedded) {
      try {
        const pack = JSON.parse(embedded);
        const font = new FontFace("PeerTree Seti", assetBytes(pack.font));
        document.fonts.add(await font.load());
        return pack.theme;
      } catch {
        // The standalone font is also available when this WebView cannot register it from bytes.
      }
    }
    const response = await fetch("/assets/seti/theme.json");
    return response.ok ? response.json() : null;
  })().catch(() => {
    fileThemeRequest = undefined;
    return null;
  });
  return fileThemeRequest;
}

function setiIcon(entry, theme) {
  if (entry.kind === "commit") return theme.icons._git;
  const filename = entry.name.toLowerCase();
  if (Object.hasOwn(theme.fileNames, filename)) return theme.icons[theme.fileNames[filename]];
  if (/(?:^|[-_.])lock(?:\.(?:json|ya?ml|toml))?$/.test(filename) ||
      ["bun.lockb", "npm-shrinkwrap.json", "go.sum"].includes(filename)) return theme.icons._lock;
  if (filename === "peertree") return theme.icons._shell;
  // Try multipart extensions, such as gitlab-ci.yml, before plain extensions.
  for (let dot = filename.indexOf("."); dot >= 0; dot = filename.indexOf(".", dot + 1)) {
    const suffix = filename.slice(dot + 1);
    if (Object.hasOwn(theme.fileExtensions, suffix)) return theme.icons[theme.fileExtensions[suffix]];
  }
  return theme.icons[theme.file];
}

function fileIcon(entry, theme) {
  const definition = entry.kind !== "tree" && theme ? setiIcon(entry, theme) : null;
  const style = definition ? " file-icon-seti" : entry.kind === "tree" ? " file-type-folder" : "";
  const icon = element("span", definition?.glyph ?? (entry.kind === "tree" ? "" : "▤"), "file-icon" + style);
  icon.setAttribute("aria-hidden", "true");
  if (definition?.color) icon.style.color = definition.color;
  return icon;
}

const syntaxAliases = {
  js: "javascript", mjs: "javascript", cjs: "javascript",
  ts: "typescript", mts: "typescript", cts: "typescript",
  py: "python", pyw: "python", python3: "python", rs: "rust",
  sh: "shell", bash: "shell", zsh: "shell", shellscript: "shell",
  htm: "html", xml: "html", svg: "html", plist: "html", vue: "html", svelte: "html",
  scss: "css", sass: "css", less: "css", jsonc: "json", yml: "yaml",
  cfg: "ini", conf: "ini", env: "ini", h: "c", cc: "cpp", cxx: "cpp", hpp: "cpp",
  cs: "csharp", rb: "ruby",
};
const syntaxFilenames = {
  ".gitignore": "ini", ".gitattributes": "ini", "cargo.lock": "toml", "bun.lock": "json",
  "pnpm-lock.yaml": "yaml", "dockerfile": "dockerfile", "containerfile": "dockerfile",
  "makefile": "makefile", "gnumakefile": "makefile", "peertree": "shell",
};
const syntaxWords = {
  javascript: "async await break case catch class const continue debugger default delete do else export extends finally for from function get if import in instanceof let new of return set static super switch this throw try typeof var void while with yield",
  typescript: "abstract as asserts declare enum implements infer interface is keyof module namespace never override private protected public readonly satisfies type unknown",
  python: "and as assert async await break case class continue def del elif else except finally for from global if import in is lambda match nonlocal not or pass raise return try while with yield",
  rust: "as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait type unsafe use where while",
  swift: "actor any as async await break case catch class continue defer deinit do else enum extension fallthrough for func guard if import in init inout is let mutating nonmutating operator private protocol public repeat return self Self some static struct subscript switch throw throws try typealias var where while",
  shell: "case do done elif else esac export fi for function if in local readonly return set then trap unset until while",
  c: "auto break case char const continue default do double else enum extern float for goto if inline int long register return short signed sizeof static struct switch typedef union unsigned void volatile while",
  cpp: "alignas constexpr class delete namespace new nullptr private protected public template typename using virtual",
  csharp: "abstract as async await base bool class delegate event foreach get interface internal namespace new override private protected public record sealed set static string this using var virtual",
  go: "break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var",
  java: "abstract assert break byte case catch class continue enum extends final finally for if implements import instanceof interface native new package private protected public return static super switch synchronized this throw throws transient try volatile while",
  ruby: "alias and begin break case class def defined do else elsif end ensure for if in module next not or redo rescue retry return self super then undef unless until when while yield",
  sql: "SELECT FROM WHERE JOIN LEFT RIGHT INNER OUTER ON ORDER BY GROUP HAVING ASC DESC INSERT INTO VALUES UPDATE SET DELETE CREATE TABLE ALTER DROP UNION LIMIT AS DISTINCT AND OR NOT EXISTS CASE WHEN THEN ELSE END",
  dockerfile: "ADD ARG CMD COPY ENTRYPOINT ENV EXPOSE FROM HEALTHCHECK LABEL ONBUILD RUN SHELL STOPSIGNAL USER VOLUME WORKDIR",
  makefile: "define else endef endif export ifdef ifeq ifndef ifneq include override private undefine unexport vpath",
};
const syntaxModes = {
  javascript: "c", typescript: "c", jsx: "react", tsx: "react",
  python: "python", rust: "rust", swift: "swift",
  c: "c", cpp: "c", csharp: "c", java: "c", go: "c", ruby: "hash", shell: "hash",
  makefile: "hash", dockerfile: "hash", json: "json", yaml: "yaml", toml: "hash",
  ini: "ini", css: "css", html: "html", sql: "sql",
};

function fileLanguage(filename, text) {
  const name = filename.split("/").at(-1).toLowerCase();
  if (Object.hasOwn(syntaxFilenames, name)) return syntaxFilenames[name];
  if (name.includes(".")) return name.split(".").at(-1);
  const interpreter = /^#![^\r\n]*\b(python[23]?|bash|zsh|sh|node|ruby)\b/.exec(text)?.[1];
  return interpreter === "node" ? "javascript" : interpreter || "";
}

const doubleQuoted = /"(?:\\[\s\S]|[^"\\\r\n])*"/.source;
const singleQuoted = /'(?:\\[\s\S]|[^'\\\r\n])*'/.source;
const multilineQuoted = /"""[\s\S]*?(?:"""|(?![\s\S]))|'''[\s\S]*?(?:'''|(?![\s\S]))/.source;
const backtickQuoted = /\x60(?:\\[\s\S]|[^\x60\\])*\x60/.source;
const cComment = /\/\/[^\r\n]*|\/\*[\s\S]*?(?:\*\/|(?![\s\S]))/.source;
const hashComment = /#[^\r\n]*/.source;
const blockComment = /\/\*[\s\S]*?(?:\*\/|(?![\s\S]))/.source;
const tagToken = /<!DOCTYPE[^>]*>|<\/?[A-Za-z][\w:.-]*(?:[^"'<>]|"[^"]*"|'[^']*')*>/.source;
const numberToken = /\b(?:0[xX][\da-fA-F_]+|0[bB][01_]+|\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d[\d_]*)?)\b/.source;
const syntaxMatchers = new Map();

function syntaxMatcher(mode) {
  if (syntaxMatchers.has(mode)) return syntaxMatchers.get(mode);
  let rules;
  if (mode === "html") {
    rules = {
      comment: /<!--[\s\S]*?(?:-->|(?![\s\S]))/.source,
      tag: tagToken,
      literal: /&(?:#\d+|#x[\da-fA-F]+|[a-zA-Z]\w*);/.source,
    };
  } else {
    const comments = {
      c: cComment, react: cComment, rust: cComment, swift: cComment, python: hashComment, hash: hashComment,
      yaml: hashComment, ini: /[;#][^\r\n]*/.source, sql: /--[^\r\n]*/.source + "|" + blockComment,
      css: blockComment, json: cComment,
    };
    const extraStrings = {
      python: multilineQuoted,
      swift: multilineQuoted,
      c: backtickQuoted,
      react: backtickQuoted,
      hash: backtickQuoted,
    };
    const strings = [extraStrings[mode], doubleQuoted, mode === "rust" ? /'(?:\\.|[^'\\\r\n])'/.source : singleQuoted];
    rules = {
      comment: comments[mode],
      tag: mode === "react" ? tagToken : undefined,
      property: {
        json: doubleQuoted + "(?=[ \\t]*:)",
        yaml: /^[ \t]*(?:-[ \t]+)?[\w.-]+(?=[ \t]*:)/.source,
        css: /(?:--)?[a-zA-Z][\w-]*(?=[ \t]*:)/.source,
        ini: /^[ \t]*[\w.-]+(?=[ \t]*=)/.source,
      }[mode],
      string: strings.filter(Boolean).join("|"),
      number: numberToken,
      variable: mode === "hash" ? /\$(?:\{[\w!#?@*-]+\}|[A-Za-z_]\w*|\d+)/.source : undefined,
      word: /[A-Za-z_]\w*/.source,
    };
  }
  const parts = Object.entries(rules).filter(([, rule]) => rule)
    .map(([kind, rule]) => "(?<" + kind + ">" + rule + ")");
  const matcher = { pattern: new RegExp(parts.join("|"), "gm"), kinds: Object.keys(rules) };
  syntaxMatchers.set(mode, matcher);
  return matcher;
}

const literalWords = new Set("true false null undefined nil none nullptr".split(" "));
const syntaxKeywords = new Map(Object.entries(syntaxWords).map(([language, words]) => {
  const inherited = language === "typescript" ? syntaxWords.javascript : language === "cpp" ? syntaxWords.c : "";
  const list = (inherited + " " + words).trim();
  // Only SQL and Dockerfile keywords are case-insensitive; Rust and Swift need `Self`.
  const caseless = language === "sql" || language === "dockerfile";
  return [language, new Set((caseless ? list.toLowerCase() : list).split(" "))];
}));

function highlightedCode(text, hint = "") {
  const code = element("code");
  const key = hint.toLowerCase().replace(/^language-/, "");
  const language = Object.hasOwn(syntaxAliases, key) ? syntaxAliases[key] : key;
  if (!Object.hasOwn(syntaxModes, language)) {
    code.textContent = text;
    return code;
  }
  const matcher = syntaxMatcher(syntaxModes[language]);
  const keywords = syntaxKeywords.get(language === "jsx" ? "javascript" : language === "tsx" ? "typescript" : language);
  let offset = 0;
  let count = 0;
  for (const token of text.matchAll(matcher.pattern)) {
    let kind = matcher.kinds.find(name => token.groups[name] !== undefined);
    if (kind === "word") {
      const word = language === "sql" || language === "dockerfile" ? token[0].toLowerCase() : token[0];
      kind = literalWords.has(word.toLowerCase()) ? "literal"
        : keywords?.has(word) ? "keyword" : null;
    }
    if (!kind) continue;
    if (++count > 30000) break;
    if (token.index > offset) code.append(document.createTextNode(text.slice(offset, token.index)));
    code.append(element("span", token[0], "syntax-" + kind));
    offset = token.index + token[0].length;
  }
  if (offset < text.length) code.append(document.createTextNode(text.slice(offset)));
  return code;
}

function markdownCode(lines, language) {
  const block = element("div", null, "markdown-code");
  const toolbar = element("div", null, "markdown-code-toolbar");
  if (language) toolbar.append(element("span", language, "markdown-code-label"));
  const pre = element("pre");
  const code = highlightedCode(lines.join("\n"), language);
  pre.append(code);
  let feedbackTimer;
  const copy = button("Copy", async () => {
    clearTimeout(feedbackTimer);
    try {
      await navigator.clipboard.writeText(code.textContent);
      copy.textContent = "Copied";
    } catch {
      const selection = window.getSelection();
      if (selection) {
        const range = document.createRange();
        range.selectNodeContents(code);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      copy.textContent = selection ? "Press ⌘C" : "Couldn’t copy";
    }
    feedbackTimer = setTimeout(() => { copy.textContent = "Copy"; }, 2500);
  }, "markdown-copy");
  copy.title = "Copy code block";
  copy.setAttribute("aria-live", "polite");
  toolbar.append(copy);
  block.append(toolbar, pre);
  return block;
}

function markdownText(text) {
  if (!text.includes("&")) return text;
  const decoder = element("textarea");
  return text.replace(/&(?:#[0-9]+|#x[\da-f]+|[a-z][a-z\d]*);/gi, entity => {
    decoder.innerHTML = entity;
    return decoder.value;
  });
}

function markdownTarget(from, href) {
  const value = markdownText(href).trim();
  if (/^(?:https?:\/\/|mailto:)/i.test(value)) return { external: value };
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(value)) return {};
  const [relative, fragment] = value.split("#", 2);
  try {
    const anchor = fragment ? decodeURIComponent(fragment) : "";
    if (!relative) return { path: from, anchor };
    const path = decodeURIComponent(relative.split("?", 1)[0]);
    const parts = path.startsWith("/") ? [] : from.split("/").slice(0, -1);
    for (const part of path.split("/")) {
      if (part === "..") {
        if (!parts.length) return {};
        parts.pop();
      } else if (part && part !== ".") {
        parts.push(part);
      }
    }
    return { path: parts.join("/"), anchor };
  } catch {
    return {};
  }
}

function markdownLink(token, context) {
  const target = markdownTarget(context.path, token.href);
  if (target.path === undefined && !target.external) {
    const label = element("span");
    renderMarkdownTokens(label, token.tokens, context);
    return label;
  }
  const link = element("a");
  link.href = target.external || (target.anchor ? "#" + encodeURIComponent(target.anchor) : "#");
  if (token.title) link.title = markdownText(token.title);
  renderMarkdownTokens(link, token.tokens, context);
  link.addEventListener("click", event => {
    event.preventDefault();
    if (target.external) {
      api("open-link", { url: target.external }).catch(error => notify(error.message, true));
    } else if (target.path === context.path && target.anchor && scrollToCodeAnchor(target.anchor)) {
      return;
    } else {
      goToPath(target.path, target.anchor);
    }
  });
  return link;
}

function markdownImage(token, context) {
  const target = markdownTarget(context.path, token.href);
  if (!target.path || target.external) {
    return target.external
      ? markdownLink({ ...token, tokens: token.tokens?.length ? token.tokens : [{ type: "text", text: token.href }] }, context)
      : element("span", markdownText(token.text));
  }
  const image = element("img", null, "markdown-image");
  image.alt = markdownText(token.text);
  if (token.title) image.title = markdownText(token.title);
  codeObject(target.path).then(file => {
    if (file.image?.data) image.src = imageSource(file.image);
  }).catch(() => {});
  return image;
}

function markdownTable(token, context) {
  const container = element("div", null, "markdown-table");
  const table = element("table");
  const head = element("thead");
  const body = element("tbody");
  for (const cells of [token.header, ...token.rows]) {
    const header = cells === token.header;
    const row = element("tr");
    for (const cell of cells) {
      const node = element(header ? "th" : "td");
      if (header) node.scope = "col";
      if (cell.align) node.style.textAlign = cell.align;
      renderMarkdownTokens(node, cell.tokens, context);
      row.append(node);
    }
    (header ? head : body).append(row);
  }
  table.append(head, body);
  container.append(table);
  return container;
}

function renderMarkdownTokens(parent, tokens, context) {
  for (const token of tokens || []) {
    let node;
    switch (token.type) {
      case "space":
        continue;
      case "heading": {
        node = element("h" + token.depth);
        renderMarkdownTokens(node, token.tokens, context);
        const title = node.textContent.trim().toLowerCase().replace(/[^\p{L}\p{N}_ -]/gu, "").replace(/ +/g, "-");
        const count = context.headings.get(title) || 0;
        context.headings.set(title, count + 1);
        node.dataset.anchor = count ? title + "-" + count : title;
        break;
      }
      case "paragraph":
      case "blockquote":
      case "strong":
      case "em":
      case "del":
        node = element(token.type === "paragraph" ? "p" : token.type);
        renderMarkdownTokens(node, token.tokens, context);
        break;
      case "list": {
        node = element(token.ordered ? "ol" : "ul");
        if (token.ordered && token.start !== 1) node.start = token.start;
        for (const item of token.items) {
          const li = element("li", null, item.task ? "markdown-task" : "");
          renderMarkdownTokens(li, item.tokens, context);
          node.append(li);
        }
        break;
      }
      case "checkbox":
        node = element("input");
        node.type = "checkbox";
        node.checked = token.checked;
        node.disabled = true;
        node.setAttribute("aria-label", token.checked ? "Completed task" : "Incomplete task");
        break;
      case "code": {
        const language = token.lang?.trim().split(/\s+/, 1)[0];
        node = markdownCode(token.text.split("\n"), language);
        break;
      }
      case "codespan":
        node = element("code", token.text, "markdown-inline-code");
        break;
      case "br":
      case "hr":
        node = element(token.type);
        break;
      case "table":
        node = markdownTable(token, context);
        break;
      case "link":
        node = markdownLink(token, context);
        break;
      case "image":
        node = markdownImage(token, context);
        break;
      case "html":
        node = token.block ? element("pre", token.text, "markdown-raw") : document.createTextNode(token.text);
        break;
      default:
        if (token.tokens) {
          renderMarkdownTokens(parent, token.tokens, context);
          continue;
        }
        node = document.createTextNode(markdownText(token.text || ""));
    }
    parent.append(node);
  }
}

function filePreview(name, text) {
  const markdown = /^readme$|\.(?:md|markdown|mdown|mkd|mdx)$/i.test(name.split("/").at(-1));
  const pre = element("pre", null, "source");
  if (markdown) {
    const preview = element("article", null, "markdown-preview");
    if (window.marked) {
      try {
        renderMarkdownTokens(preview, window.marked.lexer(text, { gfm: true }), { path: name, headings: new Map() });
        return preview;
      } catch {
        preview.replaceChildren(element("p", "This Markdown file could not be formatted.", "help"));
      }
    } else {
      preview.append(element("p", "Reopen the workspace to load Markdown formatting.", "help"));
    }
    pre.textContent = text;
    preview.append(pre);
    return preview;
  }
  pre.append(highlightedCode(text, fileLanguage(name, text)));
  return pre;
}

function imageSource(image) {
  return "data:" + image.mime + ";base64," + image.data;
}

function imagePreview(name, image) {
  if (image.data === undefined) return element("p", "Image preview is available for files up to 16 MB.", "help empty-list");
  const frame = element("div", null, "image-preview");
  const photo = element("img");
  photo.alt = name.split("/").at(-1);
  const unavailable = element("p", "This image could not be displayed.", "help");
  unavailable.hidden = true;
  photo.addEventListener("error", () => {
    photo.hidden = true;
    unavailable.hidden = false;
  });
  photo.src = imageSource(image);
  frame.append(photo, unavailable);
  return frame;
}

function codeObject(path) {
  return api("code?" + new URLSearchParams({ path }));
}

async function loadCodeWorkspace() {
  const version = screenVersion;
  const selectedPath = codePath;
  const root = await codeObject("");
  if (version !== screenVersion || !root.head) return { root, folders: new Map() };
  if (treeHead !== root.head) {
    treeHead = root.head;
    treeEntries.clear();
  }
  const folders = new Map();
  const directory = async path => {
    if (treeEntries.has(path)) return treeEntries.get(path);
    const result = await codeObject(path);
    if (version === screenVersion && result.kind === "tree" && result.head === root.head) treeEntries.set(path, result);
    return result;
  };
  const selected = selectedPath ? directory(selectedPath).catch(error => ({ error: error.message })) : null;
  await Promise.all([...openFolders].map(async path => {
    try {
      const result = await directory(path);
      if (result.kind === "tree") folders.set(path, result.entries);
    } catch {
      // A folder removed from the active commit has no tree row.
    }
  }));
  const file = await selected;
  if (version === screenVersion && selectedPath && file?.kind === "tree") {
    openFolders.add(selectedPath);
    folders.set(selectedPath, file.entries);
  }
  return { root, selectedPath, file, folders };
}

function renderFileTree(entries, folders, theme, parent = "") {
  const list = element("ul", null, "code-files");
  for (const entry of entries) {
    const path = parent ? parent + "/" + entry.name : entry.name;
    const item = element("li");
    const folder = entry.kind === "tree";
    const expanded = folder && openFolders.has(path);
    const row = button("", () => {
      if (!folder) {
        goToPath(path);
      } else {
        if (expanded) openFolders.delete(path);
        else openFolders.add(path);
        navigate("code");
      }
    }, "file-row");
    if (folder) row.setAttribute("aria-expanded", String(expanded));
    if (path === codePath) row.setAttribute("aria-current", "true");
    row.append(element("span", folder ? (expanded ? "▾" : "▸") : "", "file-chevron"),
      fileIcon(entry, theme), element("span", entry.name));
    row.disabled = !entry.preview;
    if (!entry.preview) row.title = entry.kind === "commit" ? "Git submodule" : "This filename cannot be opened here";
    item.append(row);
    if (expanded && folders.has(path)) item.append(renderFileTree(folders.get(path), folders, theme, path));
    list.append(item);
  }
  return list;
}

function scrollToCodeAnchor(anchor) {
  if (!anchor) return false;
  const heading = [...byId("code").querySelectorAll("[data-anchor]")]
    .find(item => item.dataset.anchor === anchor);
  if (heading) heading.scrollIntoView({ block: "start" });
  return !!heading;
}

function renderCode(node, workspace, theme) {
  const { root, selectedPath, file, folders } = workspace;
  if (!root.head) {
    node.replaceChildren(element("p", "This worktree has no commits yet.", "help empty-list"));
    return;
  }
  const tree = element("aside", null, "panel code-tree");
  tree.setAttribute("aria-label", "Repository files");
  tree.addEventListener("scroll", () => { treeScroll = tree.scrollTop; });
  const treeHeading = element("div", null, "panel-heading");
  treeHeading.append(element("h2", "Files"), button("Root", () => goToPath(""), "quiet"));
  tree.append(treeHeading, renderFileTree(root.entries, folders, theme));
  const panel = element("section", null, "panel code-preview");
  const heading = element("div", null, "panel-heading");
  const crumbs = element("div", null, "breadcrumbs");
  crumbs.append(button(state.project, () => goToPath(""), "quiet"));
  const current = selectedPath || root.readme?.name;
  const parts = current ? current.split("/") : [];
  for (const [index, part] of parts.entries()) {
    const currentFile = index === parts.length - 1;
    const crumb = button(currentFile ? "" : part, () => goToPath(parts.slice(0, index + 1).join("/")),
      currentFile ? "quiet code-file-crumb" : "quiet");
    if (currentFile) crumb.append(fileIcon({ name: part, kind: file?.kind || "blob" }, theme), element("span", part));
    crumbs.append(element("span", "/", "help"), crumb);
  }
  heading.append(crumbs, element("code", root.head.slice(0, 9), "help"));
  panel.append(heading);
  if (!selectedPath && root.latest) {
    const latest = element("div", null, "latest-commit");
    latest.append(element("strong", root.latest.title || "Untitled commit"),
      element("span", root.latest.author + " · " + timestamp(root.latest.at), "help"));
    panel.append(latest);
  }
  if (file?.error) {
    panel.append(element("p", file.error, "help empty-list"));
  } else if (file?.image) {
    panel.append(imagePreview(selectedPath, file.image));
  } else if (file?.text !== undefined) {
    panel.append(filePreview(selectedPath, file.text));
  } else if (!selectedPath && root.readme?.text !== undefined) {
    panel.append(filePreview(root.readme.name, root.readme.text));
  } else if (file?.kind === "blob") {
    panel.append(element("p", "Text preview is available for UTF-8 files up to 256 KB.", "help empty-list"));
  } else {
    panel.append(element("p", "Select a file from the tree to preview it.", "help empty-list"));
  }
  const layout = element("div", null, "code-layout");
  layout.append(tree, panel);
  node.replaceChildren(layout);
  tree.scrollTop = treeScroll;
  // Scroll to a followed link once, so later refreshes keep the reader's position.
  if (scrollToCodeAnchor(codeAnchor)) codeAnchor = "";
}

function renderHistory(node, rows) {
  const panel = element("section", null, "panel");
  const heading = element("div", null, "panel-heading");
  heading.append(element("h2", "Commits"), element("span", rows.length + " shown", "help"));
  panel.append(heading);
  if (!rows.length) panel.append(element("p", "This worktree has no commits yet.", "help empty-list"));
  if (!rows.some(commit => commit.id === selectedCommit)) selectedCommit = rows[0]?.id;
  const detail = element("section", null, "panel");
  const layout = element("div", null, "history-layout");
  layout.append(panel, detail);
  for (const commit of rows) {
    const item = element("div", null, "history-row");
    const refs = Object.keys(state.branches).filter(branch => state.branches[branch] === commit.id);
    const details = button("", () => {
      selectedCommit = commit.id;
      renderHistory(node, rows);
      byId("commit-" + commit.id)?.focus();
    }, "history-choice");
    details.id = "commit-" + commit.id;
    if (commit.id === selectedCommit) details.setAttribute("aria-current", "true");
    const title = element("span", null, "row");
    title.append(element("strong", commit.title || "Untitled commit"));
    for (const ref of refs) title.append(pill(ref, "accent"));
    details.append(title, element("span", commit.author + " · " + timestamp(commit.at), "help"));
    const hash = button(commit.id.slice(0, 9), async () => {
      try {
        await navigator.clipboard.writeText(commit.id);
        notify("Commit hash copied.");
      } catch {
        window.getSelection()?.selectAllChildren(hash);
      }
    }, "hash");
    hash.title = "Copy commit " + commit.id;
    item.append(element("span", "●", "commit-dot"), details, hash);
    panel.append(item);
  }
  node.replaceChildren(rows.length ? layout : panel);
  const current = rows.find(commit => commit.id === selectedCommit);
  if (current) {
    const header = element("div", null, "panel-heading");
    header.append(element("h2", current.title || "Untitled commit"), element("code", current.id.slice(0, 9), "help"));
    const changes = element("div", null, "detail-body");
    changes.append(element("p", "Loading diff…", "help"));
    detail.append(header, changes);
    Promise.all([api("commit/" + current.id), loadFileTheme()]).then(([diff, theme]) => renderDiff(changes, diff, null, theme))
      .catch(error => changes.replaceChildren(element("p", error.message, "help")));
  }
}

function timestamp(epoch) {
  const time = new Date(epoch * 1000);
  return Number.isFinite(time.getTime()) ? time.toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" });

function relativeTime(epoch) {
  if (!Number.isFinite(epoch)) return "";
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - epoch));
  if (seconds < 60) return "Just now";
  for (const [unit, length] of [["day", 86400], ["hour", 3600], ["minute", 60]]) {
    if (seconds >= length) return relative.format(-Math.floor(seconds / length), unit);
  }
}

function avatar(id) {
  const initials = name(id).trim().split(/\s+/).slice(0, 2).map(word => word[0]).join("").toUpperCase();
  const variant = parseInt(id.slice(0, 2), 16) % 4;
  return element("span", initials, "avatar avatar-" + variant);
}

function renderPeerPresence() {
  if (!state) return;
  const snapshot = nearbyPeer;
  const people = Object.keys(state.people).filter(id => id !== state.me);
  const local = element("li", null, "person");
  const self = avatar(state.me);
  self.classList.add("presence", "reachable");
  local.title = name(state.me);
  local.append(self, element("strong", "You"), element("small", "This Mac", "help"));
  const mini = [local];
  const cards = [];
  for (const id of people) {
    const paired = state.paired.includes(id);
    const reached = snapshot?.reachable?.includes(id);
    const status = reached ? "Nearby" : paired ? "Paired" : "Trusted key";
    const item = element("li", null, "person");
    const badge = avatar(id);
    badge.classList.add("presence");
    badge.classList.toggle("reachable", !!reached);
    item.append(badge, element("strong", name(id)), element("small", status, reached ? "online" : "help"));
    mini.push(item);
    const card = element("article", null, "panel peer-card");
    const heading = element("div", null, "row");
    heading.append(avatar(id), element("h2", name(id)), pill(status, reached ? "ok" : ""));
    card.append(heading, element("p", paired ? "Nearby Wi-Fi" : "Manual exchanges", "help"));
    cards.push(card);
  }
  const pair = button("", openTeam, "pair-card");
  pair.append(element("strong", "＋  Pair a nearby Mac"), element("span", "Exchange verified pairing codes in person.", "help"));
  byId("peer-mini").replaceChildren(...mini);
  const grid = byId("peer-cards");
  if (!grid.contains(document.activeElement)) grid.replaceChildren(...cards, pair);
  byId("connection-status").textContent = snapshot?.received_at ? "Latest exchange · " + relativeTime(snapshot.received_at)
    : snapshot?.enabled ? (snapshot.starting ? "Starting nearby Wi-Fi…" : "Nearby Wi-Fi")
      : snapshot ? "Nearby Wi-Fi off" : "Checking nearby…";
}

function renderActivity(node, rows) {
  const entries = rows.map(row => {
    const proposal = state.proposals.find(item => item.id === row.proposal);
    const action = {
      proposal: "submitted " + (row.title || "a branch") + " for review",
      review: (row.vote === "approve" ? "approved " : "requested changes on ") + (proposal?.title || "a branch"),
      comment: "commented on " + (proposal?.title || "a branch"),
      check: "recorded local checks for " + (proposal?.title || "a branch"),
      snapshot: "published a repository snapshot",
      quorum_root: "created a peer starting snapshot",
      shared: "published a new " + row.branch + " tip",
    }[row.kind];
    const item = element("div", null, "activity-row");
    item.append(avatar(row.who), element("span", name(row.who) + " " + action), element("span", timestamp(row.at), "help"));
    return item;
  });
  node.replaceChildren(...(entries.length ? entries : [element("p", "No signed activity yet.", "help empty-list")]));
}

function openReviewDetails(id) {
  selected = id;
  activeTab = "diff";
  navigate("reviews");
  (byId("review-inbox").hidden ? byId("detail") : byId("review-" + id))?.focus();
}

function renderReviews() {
  const items = state.proposals.map(proposal => {
    const item = button("", () => openReviewDetails(proposal.id), "proposal");
    item.id = "review-" + proposal.id;
    if (selected === proposal.id) item.setAttribute("aria-current", "true");
    const title = element("span", null, "review-title");
    const shortId = element("span", "#" + proposal.id.slice(0, 6), "review-id");
    shortId.title = proposal.id;
    title.append(shortId, element("strong", proposal.title));
    const meta = element("span", null, "review-meta");
    const author = avatar(proposal.who);
    author.title = name(proposal.who);
    const time = element("time", relativeTime(proposal.at), "help");
    if (Number.isFinite(proposal.at)) time.title = timestamp(proposal.at);
    const label = !proposal.merged && !proposal.superseded && !proposal.quorum_stale &&
        !proposal.ready && !proposal.blocked && proposal.approvals
      ? [approvalCount(proposal), ""] : status(proposal);
    meta.append(author, time, pill(...label));
    item.append(title, meta);
    return item;
  });
  byId("list").replaceChildren(...(items.length ? items :
    [element("p", "No branches submitted for review yet.", "help empty-list")]));
  renderDetail();
}

function approvalCount(proposal) {
  return proposal.approvals + " of " + proposal.required + " approvals";
}

function reviewBlockers(proposal) {
  const closed = proposal.merged ? "This revision has already merged."
    : state.quorum && proposal.quorum !== state.quorum ? "Submit this branch again under peer majority."
      : proposal.superseded ? "A newer revision is available."
        : proposal.quorum_stale ? "Rebase onto the current shared target tip and submit again." : "";
  const policy = proposal.policy_error || "";
  const review = closed || policy || (proposal.who === state.me ? "A teammate needs to review your branch." : "");
  const needsLocalCheck = !proposal.policy && (state.check || !state.quorum);
  const approve = review || (needsLocalCheck && (!proposal.run?.passed || proposal.run.command !== state.check)
    ? "Run a successful local pipeline before approving." : "");
  let merge = closed || policy;
  if (!merge && !state.quorum && !state.integrator) merge = "Choose a team mode in Settings to enable merges.";
  if (!merge && !state.quorum && state.integrator !== state.me) merge = "Only " + name(state.integrator) + " can merge as integrator.";
  if (!merge && proposal.blocked) merge = "Resolve the requested changes before merging.";
  if (!merge && !proposal.ready) {
    const missing = proposal.required - proposal.approvals;
    merge = missing > 0 ? "Merge needs " + missing + (missing === 1 ? " more approval." : " more approvals.")
      : proposal.missing.length ? "Required checks are pending." : "This revision is waiting to meet the merge requirements.";
  }
  return { review, approve, merge };
}

function renderClone() {
  const { integrator, snapshot } = state;
  const checkout = byId("clone-checkout");
  checkout.hidden = !snapshot;
  if (state.quorum && snapshot) {
    byId("clone-title").textContent = "Peer snapshot ready";
    byId("clone-status").textContent = "PeerTree will check out " + snapshot.default + " at the latest agreed tip in " + state.repo + ".";
    return;
  }
  if (state.quorum_snapshots?.length) {
    byId("clone-title").textContent = "Confirm the peer starting snapshot";
    byId("clone-status").textContent = "Open Team settings and confirm the same snapshot ID with your teammates.";
    return;
  }
  byId("clone-title").textContent = snapshot ? "Verified snapshot ready"
    : integrator ? "Waiting for the repository" : "Pair with your teammates";
  byId("clone-status").textContent = snapshot
    ? name(integrator) + " signed " + snapshot.branches.length + " protected branches and " +
      snapshot.tags + " tags. PeerTree will check out " + snapshot.default + " in " + state.repo + "."
    : integrator ? "Keep PeerTree open nearby while " + name(integrator) + " publishes the repository snapshot."
      : "Pair with both teammates, then join the starting snapshot in Team settings.";
}

function renderQuorumSettings() {
  const quorum = state.quorum;
  const snapshots = state.quorum_snapshots || [];
  const ready = Object.keys(state.people).length === 3;
  const snapshot = byId("quorum-snapshot");
  const choice = snapshot.value;
  const entries = snapshots.map(root => [root.id, root.id.slice(0, 12) + " · " + name(root.who)]);
  if (snapshot.children.length !== entries.length || entries.some(([id], index) => snapshot.children[index].value !== id)) {
    options(snapshot, entries, entries.some(([id]) => id === choice) ? choice : entries[0]?.[0]);
  }
  updateQuorumSnapshot();
  byId("quorum-status").textContent = state.quorum_error || (quorum
    ? "Peer majority is active. One teammate approval and passing checks allow two peers to advance a protected branch."
    : ready ? "Use the same starting snapshot on all three Macs to merge with peer majority."
      : "Pair with both teammates to set up peer majority.");
  byId("quorum-active-id").textContent = quorum || "";
  byId("quorum-active-id").hidden = !quorum;
  byId("quorum-init").hidden = !!quorum || !ready || state.bootstrap || !!snapshots.length;
  byId("quorum-join-form").hidden = !!quorum || !snapshots.length;
  byId("integrator-form").hidden = !!quorum;
}

function updateQuorumSnapshot() {
  const root = state?.quorum_snapshots?.find(item => item.id === byId("quorum-snapshot").value);
  byId("quorum-snapshot-id").textContent = root
    ? root.id + " · " + Object.entries(root.branches).map(([branch, hash]) => branch + " " + hash.slice(0, 9)).join(", ") : "";
}

function submissionTargets(source) {
  const head = state.branches[source];
  const alreadySubmitted = new Set(state.proposals.filter(review =>
    review.who === state.me && review.head === head && (review.quorum || null) === (state.quorum || null))
    .map(review => review.target));
  return state.protected.filter(branch => {
    const target = state.quorum ? state.shared[branch] : state.branches[branch];
    return target && target !== head && !alreadySubmitted.has(branch);
  });
}

function branchReviewActions(branch, reviews) {
  const [current, ...other] = reviews;
  if (!current) return button("Submit for review", () => openSubmission(branch));
  const group = element("div", null, "branch-review-actions");
  group.append(button("In review → " + current.target, () => openReviewDetails(current.id)));
  const canSubmit = submissionTargets(branch).length > 0;
  if (!other.length && !canSubmit) return group;
  const dropdown = element("details", null, "branch-review-menu");
  dropdown.setAttribute("name", "branch-review-menu");
  const summary = element("summary", "⌄");
  summary.setAttribute("aria-label", "More review options for " + branch);
  const choices = element("div", null, "branch-review-options");
  for (const review of other) {
    const action = button("", () => openReviewDetails(review.id));
    action.append(element("span", "Review into " + review.target), element("small", review.title, "help"));
    choices.append(action);
  }
  if (canSubmit) choices.append(button("Submit another review…", () => openSubmission(branch)));
  dropdown.addEventListener("keydown", event => {
    if (event.key === "Escape" && dropdown.open) {
      dropdown.open = false;
      summary.focus();
    }
  });
  dropdown.append(summary, choices);
  group.append(dropdown);
  return group;
}

function renderBranches() {
  const isIntegrator = !state.quorum && state.integrator === state.me;
  byId("publish").hidden = !isIntegrator;
  byId("snapshot-open").hidden = !isIntegrator;
  const heading = element("div", null, "panel-heading");
  heading.append(element("h2", "Branches"));
  const rows = [];
  const labels = { synced: "Synced", ahead: "Ahead", behind: "Behind", diverged: "Diverged",
    missing: "Local branch missing" };
  const activeReviews = new Map();
  for (const review of state.proposals) {
    if (review.who !== state.me || review.merged || review.superseded || review.quorum_stale) continue;
    if (!activeReviews.has(review.source)) activeReviews.set(review.source, []);
    activeReviews.get(review.source).push(review);
  }
  for (const branch of new Set([...state.protected, ...Object.keys(state.branches)])) {
    const local = state.branches[branch];
    const published = state.shared[branch];
    const protectedBranch = state.protected.includes(branch);
    const relation = state.branch_status[branch];
    const item = element("article", null, "branch");
    const label = element("div", null, "branch-label");
    const title = element("div", null, "row");
    title.append(element("strong", branch), protectedBranch ? pill("Protected") : pill("Local"));
    label.append(title, element("div", [local && "Local " + local.slice(0, 9),
      published && "Signed " + published.slice(0, 9)].filter(Boolean).join("  ·  ") || "No branch tip", "branch-info"));
    item.append(label);
    if (protectedBranch) {
      if (labels[relation]) {
        item.append(pill(labels[relation], relation === "diverged" ? "alert" : relation === "synced" ? "ok" : ""));
      }
      if (relation === "behind" || relation === "missing") {
        item.append(button(relation === "behind" ? "Fast-forward" : "Check out",
          () => change("sync", { branch }, null, "Updating " + branch + "…")));
      }
      if (relation === "diverged") item.append(element("span", "Reconcile in Git", "help"));
    } else {
      item.append(branchReviewActions(branch, activeReviews.get(branch) || []));
    }
    rows.push(item);
  }
  byId("branches").replaceChildren(heading, ...rows);
}

function renderDetail() {
  const container = byId("detail");
  const proposal = state.proposals.find(item => item.id === selected);
  const version = ++diffVersion;
  if (!proposal) {
    const empty = element("div", null, "empty-detail");
    empty.append(element("h2", "Review a branch together"),
      element("p", "Submit a local branch or import a teammate’s exchange.", "help"),
      button("Import exchange", () => byId("import").click()));
    container.replaceChildren(empty);
    return;
  }

  const heading = element("div", null, "detail-header");
  const meta = element("div", null, "row");
  if (proposal.merged || proposal.superseded || proposal.blocked) meta.append(pill(...status(proposal)));
  if (proposal.policy_error) {
    meta.append(pill("Policy error", "alert"));
  } else if (proposal.pipeline_status) {
    meta.append(pill(proposal.pipeline_status === "running" ? "Pipeline running" : "Pipeline queued", "accent"));
  } else if (proposal.policy && proposal.checks.length) {
    if (!proposal.missing.length) meta.append(pill("Pipeline passed", "ok"));
    else if ((currentRun(proposal) && !proposal.run.passed) ||
        proposal.check_runs?.some(check => !check.passed && proposal.missing.includes(check.check))) {
      meta.append(pill("Pipeline failed", "alert"));
    } else {
      meta.append(pill("Checks pending"));
    }
  } else if (currentRun(proposal)) {
    const passed = proposal.run.passed;
    meta.append(pill(passed ? "Pipeline passed" : "Pipeline failed", passed ? "ok" : "alert"));
  }
  const summary = element("div", null, "review-summary row");
  const revision = element("span", "#" + proposal.id.slice(0, 6), "review-id");
  revision.title = "Revision " + proposal.head;
  const title = element("h2", proposal.title + " ");
  title.append(revision);
  summary.append(avatar(proposal.who), element("span", name(proposal.who)), element("span", "wants to merge"),
    element("code", proposal.source), element("span", "→"), element("code", proposal.target));
  if (meta.children.length) heading.append(meta);
  heading.append(title, summary);

  const tabs = element("div", null, "tabs");
  tabs.setAttribute("aria-label", "Review sections");
  const discussion = proposal.comments.length + proposal.reviews.length;
  for (const [id, label] of [["diff", "Changes"], ["check", "Pipeline"],
    ["reviews", discussion ? "Discussion · " + discussion : "Discussion"]]) {
    const tab = button(label, () => {
      activeTab = id;
      renderDetail();
      byId("tab-" + id)?.focus();
    }, "tab");
    tab.id = "tab-" + id;
    tab.setAttribute("aria-pressed", String(activeTab === id));
    tabs.append(tab);
  }
  const body = element("div", null, "detail-body");
  const approvalBar = element("div", null, "review-approval");
  const voters = element("div", null, "row");
  for (const review of proposal.reviews.filter(item => item.vote === "approve")) {
    const badge = avatar(review.who);
    badge.title = name(review.who) + " approved";
    voters.append(badge);
  }
  voters.append(pill(approvalCount(proposal)));
  approvalBar.append(voters);
  const controls = element("div", null, "row");
  controls.setAttribute("role", "group");
  controls.setAttribute("aria-label", "Review actions");
  const blockers = reviewBlockers(proposal);
  const actions = [
    [button("Request changes", () => openReview(proposal, "changes")), blockers.review],
    [button("✓ Approve", () => openReview(proposal, "approve"), "primary"), blockers.approve],
    [button(proposal.quorum_pending ? "Retry peer merge" : "Merge into " + proposal.target, () => change("integrate",
      { id: proposal.id, revision: proposal.head }, null, "Merging and publishing branch tips…"), "primary"), blockers.merge],
  ];
  for (const [action, reason] of actions) {
    action.disabled = !!reason;
    if (reason) action.title = reason;
    controls.append(action);
  }
  approvalBar.append(controls);
  const guidance = [...new Set([blockers.approve, blockers.merge].filter(Boolean))];
  if (proposal.quorum_pending && !blockers.merge) guidance.push("Sync with a teammate to finish the automatic peer merge.");
  if (guidance.length) approvalBar.append(element("p", guidance.join(" "), "help review-guidance"));
  heading.append(approvalBar, tabs);
  container.replaceChildren(heading, body);

  if (activeTab === "diff") {
    body.append(element("p", "Loading diff…", "help"));
    Promise.all([api("diff/" + proposal.id), loadFileTheme()]).then(([diff, theme]) => {
      if (version === diffVersion) renderDiff(body, diff, proposal, theme);
    }).catch(error => {
      if (version === diffVersion) body.replaceChildren(element("p", error.message, "help"));
    });
  } else if (activeTab === "check") {
    renderPipeline(body, proposal);
  } else {
    renderDiscussion(body, proposal);
  }
}

function diffFiles(patch, paths = []) {
  const files = [];
  let file;
  let oldLine, newLine;
  for (const line of patch.replace(/\n$/, "").split("\n")) {
    if (line.startsWith("diff --git ")) {
      const pair = paths[files.length];
      file = { name: pair?.new || pair?.old || line.slice(11), pair, lines: [], added: 0, removed: 0 };
      files.push(file);
      oldLine = newLine = undefined;
      continue;
    }
    if (!file) continue;
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) {
      oldLine = Number(hunk[1]);
      newLine = Number(hunk[2]);
      file.lines.push([line, "hunk", "", ""]);
    } else if (oldLine === undefined) {
      if (!file.pair && line.startsWith("rename to ")) file.name = line.slice(10);
      if (!file.pair && (line.startsWith("+++ ") || line.startsWith("--- ") && !file.path)) {
        const path = line.slice(4).replace(/\t$/, "");
        if (path !== "/dev/null") {
          file.name = path.replace(/^[ab]\//, "");
          file.path = true;
        }
      }
      file.lines.push([line, "metadata", "", ""]);
    } else if (line.startsWith("+")) {
      file.added++;
      file.lines.push([line, "add", "", newLine++]);
    } else if (line.startsWith("-")) {
      file.removed++;
      file.lines.push([line, "remove", oldLine++, ""]);
    } else if (line.startsWith(" ")) {
      file.lines.push([line, "", oldLine++, newLine++]);
    } else {
      file.lines.push([line, "metadata", "", ""]);
    }
  }
  return files;
}

function anchorKey({ file, side, line }) {
  return JSON.stringify([file, side, line]);
}

function anchorLabel({ file, side, line }) {
  return file + ":" + line + (side === "old" ? " (old)" : "");
}

function inlineCommentForm(proposal, anchor, editor) {
  const form = element("form", null, "comment-form inline-comment-form");
  const label = element("label", "Comment on " + anchorLabel(anchor));
  const input = element("textarea");
  input.required = true;
  input.maxLength = 4000;
  label.append(input);
  const controls = element("div", null, "row");
  const post = element("button", "Post comment", "primary");
  post.type = "submit";
  controls.append(post, button("Cancel", () => {
    const thread = editor.parentElement;
    editor.remove();
    if (!thread.childElementCount) thread.remove();
  }));
  form.append(label, controls);
  form.addEventListener("submit", event => {
    event.preventDefault();
    change("comment", { id: proposal.id, body: input.value, anchor }, () => {
      requestedComment = { proposal: proposal.id, anchor };
    });
  });
  editor.replaceChildren(form);
  input.focus();
}

function renderDiff(body, diff, proposal, theme) {
  const files = diffFiles(diff.patch, diff.paths);
  const threads = new Map();
  for (const comment of proposal?.comments || []) {
    if (comment.anchor) {
      const key = anchorKey(comment.anchor);
      if (!threads.has(key)) threads.set(key, []);
      threads.get(key).push(comment);
    }
  }
  const requested = requestedComment && requestedComment.proposal === proposal?.id ? requestedComment : null;
  if (requested) requestedComment = undefined;
  body.replaceChildren();
  if (diff.truncated) body.append(element("p", "Showing the first 300 KB of this diff. Use Git to inspect the full change.", "diff-warning"));
  if (!files.length) {
    body.append(element("pre", diff.stats || "No file changes.", "help"));
    return;
  }
  const renderFile = file => {
    const panel = element("section", null, "file-diff");
    const header = element("div", null, "diff-header");
    header.append(fileIcon({ name: file.name.split("/").at(-1), kind: "blob" }, theme),
      element("code", file.name), element("span", "+" + file.added, "online"),
      element("span", "−" + file.removed, "removed-text"));
    const patch = element("div", null, "patch");
    const fragment = document.createDocumentFragment();
    const firstHunk = file.lines.findIndex(([, type]) => type === "hunk");
    const visible = firstHunk < 0 ? file.lines : file.lines.filter(([line, type], index) =>
      index >= firstHunk || type === "metadata" && /^(?:old mode|new mode|new file mode|deleted file mode|rename from|rename to|copy from|copy to) /.test(line));
    for (const [line, type, oldLine, newLine] of visible) {
      const row = element("div", null, "diff-line " + type);
      const below = [];
      for (const [side, number] of [["old", oldLine], ["new", newLine]]) {
        if (proposal && number && file.pair?.[side]) {
          const anchor = { file: file.pair[side], side, line: number };
          const key = anchorKey(anchor);
          const comments = threads.get(key) || [];
          const gutter = button(number, () => {
            let thread = [...patch.querySelectorAll("[data-comment-line]")].find(item => item.dataset.commentLine === key);
            if (!thread) {
              thread = element("div", null, "inline-thread");
              thread.dataset.commentLine = key;
              row.after(thread);
            }
            let editor = thread.querySelector(".inline-editor");
            const draft = editor?.querySelector("textarea");
            if (draft) {
              draft.focus();
              return;
            }
            if (!editor) {
              editor = element("div", null, "inline-editor");
              thread.append(editor);
            }
            inlineCommentForm(proposal, anchor, editor);
          }, "gutter gutter-comment");
          gutter.title = "Comment on " + anchorLabel(anchor);
          gutter.setAttribute("aria-label", gutter.title + (comments.length ? " · " + comments.length + " comments" : ""));
          if (comments.length) {
            gutter.classList.add("has-comments");
            const thread = element("div", null, "inline-thread");
            thread.dataset.commentLine = key;
            thread.append(element("div", anchorLabel(anchor), "inline-location"));
            for (const comment of comments) {
              const item = element("div", null, "inline-message");
              item.append(element("strong", name(comment.who)), element("time", timestamp(comment.at), "help"),
                element("p", comment.body));
              thread.append(item);
            }
            below.push(thread);
          }
          row.append(gutter);
        } else {
          const gutter = element("span", number, "gutter");
          gutter.setAttribute("aria-hidden", "true");
          row.append(gutter);
        }
      }
      row.append(element("code", line || " "));
      fragment.append(row, ...below);
    }
    patch.append(fragment);
    panel.append(header, patch);
    return panel;
  };
  const sections = document.createDocumentFragment();
  for (const file of files) sections.append(renderFile(file));
  body.append(sections);
  if (requested) {
    const key = anchorKey(requested.anchor);
    const thread = [...body.querySelectorAll("[data-comment-line]")].find(item => item.dataset.commentLine === key);
    thread?.scrollIntoView({ block: "nearest" });
  }
}

function currentRun(proposal) {
  return proposal.run && proposal.run.policy === proposal.policy &&
    (proposal.policy || proposal.run.command === state.check);
}

function renderPipeline(body, proposal) {
  const output = proposal.run;
  const controls = element("div", null, "row");
  const run = button(currentRun(proposal) ? "Rerun local pipeline" : "Run local pipeline", () => change("check", { id: proposal.id },
    null, "Running the pipeline for " + proposal.head.slice(0, 9) + "…"), "primary");
  run.disabled = !!state.running_check || !!proposal.policy_error || (!proposal.policy && !state.check);
  controls.append(run);
  if (proposal.pipeline_status) controls.append(pill(proposal.pipeline_status === "running" ? "Running" : "Queued", "accent"));
  else if (currentRun(proposal)) controls.append(pill((output.passed ? "Passed" : "Failed") + " · " + output.secs + "s",
    output.passed ? "ok" : "alert"));
  body.append(controls);
  if (proposal.policy_error) body.append(element("p", proposal.policy_error, "help"));
  else if (proposal.policy) {
    body.append(element("p", proposal.checks.length
      ? "Required checks · " + proposal.checks.join(", ") : "This policy has no required checks.", "help"));
    if (proposal.missing.length) body.append(element("p", "Waiting for · " + proposal.missing.join(", "), "help"));
    if (proposal.who !== state.me && proposal.checks.length && !currentRun(proposal)) {
      body.append(element("p", "Checks run this branch's code on your Mac. Review the changes, then run the pipeline.", "help"));
    }
  } else {
    const shared = state.shared[proposal.target];
    const tip = shared || state.branches[proposal.target];
    const target = (shared ? "Shared " : "Local ") + proposal.target + (tip ? " · " + tip.slice(0, 9) : "");
    const explanation = element("div", null, "pipeline-policy");
    explanation.append(element("strong", "No active repository pipeline"),
      element("p", target + " has no committed pipeline policy.", "help"));
    if (state.policy_in_worktree) {
      explanation.append(element("p",
        "This checkout contains .peertree.json. It takes effect when the target branch contains the policy and the submitted revision includes its check scripts.", "help"));
    }
    if (state.check) {
      explanation.append(element("code", state.check, "help"));
    } else {
      explanation.append(button("Configure fallback command", () => navigate("settings"), "quiet"));
    }
    body.append(explanation);
  }
  body.append(element("p", "The pipeline runs on this Mac in a temporary checkout of the submitted commit.", "help"));
  for (const check of proposal.check_runs || []) {
    const item = element("div", null, "check-row");
    item.append(avatar(check.who), element("strong", name(check.who)), element("code", check.check),
      pill(check.passed ? "Passed" : "Failed", check.passed ? "ok" : "alert"));
    body.append(item);
  }
  if (output) {
    if (!currentRun(proposal)) body.append(element("p", "This log used an earlier pipeline configuration.", "help"));
    body.append(element("pre", output.output, "pipeline-output"));
  }
}

function renderDiscussion(body, proposal) {
  const messages = [...proposal.reviews, ...proposal.comments].sort((a, b) => a.at - b.at);
  if (!messages.length) body.append(element("p", "No discussion yet.", "help"));
  for (const message of messages) {
    const item = element("div", null, "review-item");
    const heading = element("div", null, "row");
    heading.append(avatar(message.who), element("strong", name(message.who)),
      element("span", timestamp(message.at), "help"));
    if (message.vote) {
      const approved = message.vote === "approve";
      heading.append(pill(approved ? "Approved" : "Changes requested", approved ? "ok" : "alert"));
    }
    if (message.anchor) {
      heading.append(button(anchorLabel(message.anchor), () => {
        requestedComment = { proposal: proposal.id, anchor: message.anchor };
        activeTab = "diff";
        renderDetail();
      }, "quiet inline-jump"));
    }
    item.append(heading);
    if (message.note || message.body) item.append(element("p", message.note || message.body));
    body.append(item);
  }
  const form = element("form", null, "comment-form");
  const label = element("label", "Comment");
  const input = element("textarea");
  input.maxLength = 4000;
  input.placeholder = "Leave feedback for your teammates";
  input.required = true;
  label.append(input);
  const submit = element("button", "Post comment");
  submit.type = "submit";
  form.append(label, submit);
  form.addEventListener("submit", event => {
    event.preventDefault();
    change("comment", { id: proposal.id, body: input.value });
  });
  body.append(form);
}

let pendingReview;
function openReview(proposal, vote) {
  pendingReview = { id: proposal.id, revision: proposal.head, vote };
  const label = vote === "approve" ? "Approve revision" : "Request changes";
  byId("review-heading").textContent = label;
  byId("review-submit").textContent = label;
  byId("review-revision").textContent = proposal.title + " · " + proposal.head.slice(0, 9);
  byId("review-form").reset();
  byId("review-dialog").showModal();
}

function options(select, entries, chosen, placeholder) {
  select.replaceChildren();
  if (placeholder) {
    const first = new Option(placeholder, "");
    first.disabled = true;
    select.append(first);
  }
  for (const [value, label] of entries) select.append(new Option(label, value));
  if (chosen != null) select.value = chosen;
  else if (placeholder) select.value = "";
}

function setupTeam() {
  byId("public-key").value = state.public;
  byId("check-command").value = state.check;
  updatePipelineSave();
  const eligible = Object.entries(state.people).filter(([id]) => !state.bootstrap || id !== state.me);
  options(byId("integrator"), eligible, state.integrator, "Choose an integrator");
  byId("reset-pairing-form").hidden = state.paired.length === 0;
  options(byId("reset-pairing"), state.paired.map(id => [id, name(id)]));
  updatePairingCode();
}

function updatePairingCode() {
  byId("peer-invite").hidden = !nearbyPeer?.code;
  byId("pair-help").textContent = nearbyPeer?.code ? "Verify and exchange codes on both Macs in person."
    : "Verify public keys in person for manual exchanges. Start PeerTree with nearby Wi-Fi enabled to get a pairing code.";
  const invite = byId("peer-code");
  if (nearbyPeer?.code && invite.value !== nearbyPeer.code) invite.value = nearbyPeer.code;
  const code = byId("settings-pair-code");
  const value = nearbyPeer?.code || "";
  if (code.value !== value) {
    code.value = value;
    byId("settings-copy-status").hidden = true;
  }
  byId("settings-copy-code").disabled = !value;
  byId("settings-pair-help").textContent = value
    ? "Contains your public signing key and certificate fingerprint. Verify codes with your teammate in person."
    : nearbyPeer?.starting ? "Starting nearby Wi-Fi…"
      : "Open PeerTree with nearby Wi-Fi enabled to generate a pairing code.";
}

function updatePipelineSave() {
  byId("save-pipeline").hidden = byId("check-command").value.trim() === state.check;
}

for (const close of document.querySelectorAll("dialog .close")) {
  close.addEventListener("click", () => close.closest("dialog").close());
}
for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("close", () => dialog.querySelector(".dialog-error")?.remove());
}

function openTeam() {
  if (!state) return;
  setupTeam();
  byId("key-status").textContent = "";
  byId("peer-code-status").textContent = "";
  byId("team-dialog").showModal();
}
byId("team-open").addEventListener("click", openTeam);
byId("quorum-snapshot").addEventListener("change", updateQuorumSnapshot);
byId("quorum-init").addEventListener("click", () => change("team", { action: "quorum-init" }));
byId("quorum-join-form").addEventListener("submit", event => {
  event.preventDefault();
  change("team", { action: "quorum-join", id: byId("quorum-snapshot").value },
    () => { if (state.bootstrap) view = "clone"; });
});
byId("clone-pair").addEventListener("click", openTeam);
byId("clone-checkout").addEventListener("click", () => change("checkout", {}, null, "Checking out repository…"));
async function copyFrom(field, status, successMessage) {
  byId(status).hidden = false;
  try {
    await navigator.clipboard.writeText(byId(field).value);
    byId(status).textContent = successMessage;
  } catch {
    byId(field).select();
    byId(status).textContent = "Press Command-C to copy the selected text.";
  }
}
byId("settings-copy-code").addEventListener("click", () =>
  copyFrom("settings-pair-code", "settings-copy-status", "Pairing code copied."));
byId("check-command").addEventListener("input", updatePipelineSave);
byId("prune-cache").addEventListener("click", () => change("prune-cache", {}));
for (const toggle of document.querySelectorAll("[data-notification]")) {
  toggle.addEventListener("change", async () => {
    const category = toggle.dataset.notification;
    toggle.disabled = true;
    await change("team", { action: "notification", category, enabled: toggle.checked });
    toggle.checked = !!state.notifications?.[category];
    toggle.disabled = false;
  });
}
byId("copy-key").addEventListener("click", () => copyFrom("public-key", "key-status", "Public key copied."));
byId("copy-peer-code").addEventListener("click", () =>
  copyFrom("peer-code", "peer-code-status", "Pairing code copied."));
function openSubmission(source) {
  return perform(async () => {
    await refresh();
    const form = byId("proposal-form");
    const branches = Object.keys(state.branches);
    const current = state.worktrees.find(worktree => worktree.path === state.repo)?.branch;
    options(form.elements.source, branches.map(branch => [branch, branch]),
      source || (current && !state.protected.includes(current) ? current :
        branches.find(branch => !state.protected.includes(branch))), "Choose a source branch");
    const updateTargets = () => {
      const targets = submissionTargets(form.elements.source.value);
      options(form.elements.target, targets.map(branch => [branch, branch]),
        targets.length === 1 ? targets[0] : undefined,
        targets.length ? "Choose a protected target" : "No new targets for this commit");
      byId("submit-review").disabled = targets.length === 0;
    };
    form.elements.source.onchange = updateTargets;
    updateTargets();
    byId("proposal-dialog").showModal();
  });
}
byId("snapshot-open").addEventListener("click", () => perform(async () => {
  await refresh();
  const form = byId("snapshot-form");
  const choices = state.snapshot_sources;
  const selection = byId("snapshot-branches");
  const initial = new Set(state.protected.filter(branch => choices.includes(branch)));
  if (!initial.size && choices.length) initial.add(choices[0]);
  selection.replaceChildren(...choices.map(branch => {
    const label = element("label");
    const box = element("input");
    box.type = "checkbox";
    box.name = "branches";
    box.value = branch;
    box.checked = initial.has(branch);
    label.append(box, document.createTextNode(branch));
    return label;
  }));
  const updateDefaults = previous => {
    const chosen = new FormData(form).getAll("branches");
    options(form.elements.default, chosen.map(ref => [ref, ref]),
      chosen.includes(previous) ? previous : chosen.includes("main") ? "main" : chosen[0]);
  };
  selection.onchange = () => updateDefaults(form.elements.default.value);
  updateDefaults(state.snapshot?.default);
  byId("snapshot-dialog").showModal();
}));
byId("snapshot-form").addEventListener("submit", event => {
  event.preventDefault();
  const fields = new FormData(event.target);
  change("snapshot", { branches: fields.getAll("branches"), default: fields.get("default") },
    () => byId("snapshot-dialog").close(), "Publishing repository snapshot…");
});
const importButton = byId("import");
importButton.addEventListener("click", () => byId("file").click());
importButton.addEventListener("dragover", event => {
  if (!event.dataTransfer.types.includes("Files")) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = "copy";
  importButton.classList.add("drop-target");
});
importButton.addEventListener("dragleave", () => importButton.classList.remove("drop-target"));
importButton.addEventListener("drop", event => {
  event.preventDefault();
  importButton.classList.remove("drop-target");
  const files = event.dataTransfer.files;
  if (files.length !== 1 || !files[0].name.toLowerCase().endsWith(".zip")) {
    notify("Drop one exchange ZIP at a time.", true);
    return;
  }
  change("import", files[0], null, "Importing exchange…");
});
byId("worktree").addEventListener("change", async event => {
  const path = event.target.value;
  event.target.value = state.repo;
  await change("worktree", { path });
});
byId("file").addEventListener("change", event => {
  const [file] = event.target.files;
  event.target.value = "";
  if (file) change("import", file, null, "Importing exchange…");
});
byId("export").addEventListener("click", () => perform(async () => {
  const blob = await api("export");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "neighbor-exchange-" + new Date().toISOString().slice(0, 10) + ".zip";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  notify("Exchange exported. Share the ZIP with your teammates.");
}, "Preparing exchange…"));
byId("share").addEventListener("click", () => change("share", {}, null, "Preparing exchange for Finder…"));

byId("proposal-form").addEventListener("submit", event => {
  event.preventDefault();
  change("propose", Object.fromEntries(new FormData(event.target)), () => {
    event.target.reset();
    byId("proposal-dialog").close();
  });
});
for (const [form, action] of [["peer-form", "add"], ["reset-pairing-form", "reset-pairing"], ["integrator-form", "integrator"],
  ["check-form", "check"]]) {
  byId(form).addEventListener("submit", async event => {
    event.preventDefault();
    const input = { action, ...Object.fromEntries(new FormData(event.target)) };
    const saved = await change("team", input, () => {
      if (action === "add") event.target.reset();
      event.target.closest("dialog")?.querySelector(".dialog-error")?.remove();
    });
    if (saved) setupTeam();
  });
}
for (const item of document.querySelectorAll("[data-view]")) {
  item.addEventListener("click", () => navigate(item.dataset.view));
}
document.addEventListener("pointerdown", event => {
  const menu = document.querySelector(".branch-review-menu[open]");
  if (menu && !menu.contains(event.target)) menu.open = false;
});
byId("peer-link").addEventListener("click", () => navigate("peers"));
byId("divergence-open").addEventListener("click", () => navigate("branches"));
byId("clone-import").addEventListener("click", () => byId("import").click());
byId("clone-settings").addEventListener("click", () => navigate("settings"));
byId("new").addEventListener("click", () => openSubmission());
byId("review-list-toggle").addEventListener("click", event => {
  const control = event.currentTarget;
  const inbox = byId("review-inbox");
  inbox.hidden = !inbox.hidden;
  byId("review-layout").classList.toggle("review-list-hidden", inbox.hidden);
  control.setAttribute("aria-expanded", String(!inbox.hidden));
  control.textContent = inbox.hidden ? "Show reviews" : "Hide reviews";
});
byId("wrap-review-lines").addEventListener("change", event => {
  byId("review-layout").classList.toggle("wrap-review-lines", event.currentTarget.checked);
});
byId("branches-new").addEventListener("click", () => openSubmission());
byId("publish").addEventListener("click", () => change("publish", {}, null, "Publishing signed branch tips…"));
byId("refresh").addEventListener("click", () => change("refresh", {}, null, "Refreshing team tracking refs…"));
byId("review-form").addEventListener("submit", event => {
  event.preventDefault();
  change("review", { ...pendingReview, note: event.target.elements.note.value }, () => {
    activeTab = "reviews";
    byId("review-dialog").close();
  });
});

const commandDialog = byId("commands-dialog");
const commandFilter = byId("commands-filter");
function renderCommands() {
  const filter = commandFilter.value.trim().toLowerCase();
  const available = Object.entries(views).filter(([screen]) => state.bootstrap
    ? ["peers", "settings", "clone"].includes(screen) : screen !== "clone");
  const commands = available.map(([screen, label]) => [label, () => navigate(screen)]);
  commands.push(["Pair a Mac", openTeam], ["Sync now", () => byId("refresh").click()],
    ["Import exchange", () => byId("import").click()], ["Export exchange", () => byId("export").click()]);
  if (!state.bootstrap) commands.push(["Submit branch for review", () => openSubmission()]);
  const results = commands.filter(([label]) => label.toLowerCase().includes(filter)).map(([label, action]) =>
    button(label, () => { commandDialog.close(); action(); }, "command"));
  byId("commands-results").replaceChildren(...(results.length ? results : [element("p", "No matching actions.", "help")]));
}
function openCommands() {
  if (!state || document.querySelector("dialog[open]")) return;
  commandFilter.value = "";
  renderCommands();
  commandDialog.showModal();
  commandFilter.focus();
}
byId("commands-open").addEventListener("click", openCommands);
commandFilter.addEventListener("input", renderCommands);
commandDialog.addEventListener("keydown", event => {
  const actions = [...commandDialog.querySelectorAll(".command")];
  if (event.key === "Enter" && document.activeElement === commandFilter && actions.length) {
    event.preventDefault();
    actions[0].click();
  } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    const index = actions.indexOf(document.activeElement);
    const next = event.key === "ArrowDown" ? index + 1 : index < 0 ? actions.length - 1 : index - 1;
    event.preventDefault();
    (actions[next] || commandFilter).focus();
  }
});
document.addEventListener("keydown", event => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openCommands();
  }
});

refresh().then(checkNearby).catch(error => notify(error.message, true));
setInterval(checkNearby, 4000);
