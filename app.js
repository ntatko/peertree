"use strict";

const byId = id => document.getElementById(id);
const token = document.querySelector('meta[name="neighbor-token"]').content;
let state;
let selected;
let activeTab = "diff";
let diffVersion = 0;
let busy = false;
const seenNotices = new Set();
const desktopAlerts = byId("desktop-alerts");
let nearbyPolling = false;
let seenExchanges = 0;
let renderedExchanges = 0;
let nearbyPeer;

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

function notify(text, error = false) {
  const node = byId("notice");
  node.textContent = text;
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
  state = await api("state");
  if (!state.proposals.some(proposal => proposal.id === selected)) {
    selected = state.proposals[0]?.id;
  }
  render();
}

async function checkNearby() {
  if (nearbyPolling) return;
  nearbyPolling = true;
  try {
    const { enabled, error, notices, peer } = await api("nearby");
    nearbyPeer = peer;
    updatePairingCode();
    byId("nearby").hidden = !enabled && !peer.enabled;
    if (!enabled && !peer.enabled) return;
    desktopAlerts.hidden = typeof Notification === "undefined" || Notification.permission !== "default";
    const status = byId("nearby-status");
    const rows = notices.map(notice => {
      const message = notice.name + " submitted a branch for review. Import their exchange to open it.";
      if (!seenNotices.has(notice.id) && window.Notification?.permission === "granted") {
        try { new Notification("PeerTree", { body: message, tag: notice.id }); }
        catch { /* The nearby activity panel also shows this alert. */ }
      }
      seenNotices.add(notice.id);
      return element("p", message);
    });
    if (peer.enabled) {
      const nearby = peer.online.length ? "Connected recently · " + peer.online.join(", ")
        : "Looking for paired teammates on nearby Wi-Fi.";
      rows.unshift(element("p", peer.starting ? "Starting nearby Wi-Fi…" : (peer.error || nearby)));
      for (const activity of peer.activity) rows.push(element("p", activity));
      if (peer.received_count > seenExchanges) {
        seenExchanges = peer.received_count;
        if (window.Notification?.permission === "granted") {
          try { new Notification("PeerTree", { body: peer.activity[0] || peer.received }); }
          catch { /* The nearby activity panel also shows this alert. */ }
        }
      }
      if (peer.received_count > renderedExchanges && !busy &&
          !document.querySelector("dialog[open]") && !document.activeElement?.matches("input,textarea,select")) {
        await refresh();
        renderedExchanges = peer.received_count;
      }
    } else {
      if (error) rows.unshift(element("p", "LAN alerts unavailable. " + error));
      if (!rows.length) rows.push(element("p", "Listening for reviews from trusted teammates on the LAN."));
    }
    if (status.textContent !== rows.map(row => row.textContent).join("")) status.replaceChildren(...rows);
  } catch {
    // The next poll retries after a temporary connection error.
  } finally {
    nearbyPolling = false;
  }
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
    await action();
  } catch (error) {
    notify(error.message, true);
  } finally {
    if (active?.tagName === "BUTTON") active.disabled = false;
    busy = false;
  }
}

function change(path, input, onSuccess, waiting) {
  return perform(async () => {
    const result = await api(path, input);
    if (result.selected) {
      selected = result.selected;
      activeTab = "diff";
    }
    if (onSuccess) onSuccess();
    await refresh();
    if (path === "import") await checkNearby();
    notify(result.message || (path === "check"
      ? (result.passed ? "Pipeline passed." : "Pipeline failed. Review the output below.")
      : (nearbyPeer?.enabled ? "Branch submitted. Paired teammates receive it when nearby."
        : "Branch submitted for review. Export an exchange to share it.")));
  }, waiting);
}

function status(proposal) {
  if (proposal.merged) return ["Merged", "ok"];
  if (proposal.superseded) return ["Superseded", ""];
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

function render() {
  byId("project").textContent = state.project;
  byId("page-title").textContent = state.bootstrap ? "Clone repository" : "Code review";
  byId("worktree-picker").hidden = state.bootstrap;
  byId("review-layout").hidden = state.bootstrap;
  byId("branches").hidden = state.bootstrap;
  byId("new").hidden = state.bootstrap;
  byId("export").hidden = state.bootstrap;
  byId("share").hidden = state.bootstrap;
  byId("snapshot-open").hidden = state.bootstrap || state.integrator !== state.me;
  byId("clone").hidden = !state.bootstrap;
  if (state.bootstrap) {
    renderClone();
    return;
  }
  options(byId("worktree"), state.worktrees.map(({ path, branch }) =>
    [path, path.split("/").at(-1) + " · " + (branch || "detached HEAD")]), state.repo);
  byId("worktree").title = state.repo;
  byId("worktree").disabled = state.worktrees.length < 2;
  byId("avatar").textContent = name(state.me).split(/\s+/).slice(0, 2).map(word => word[0]).join("").toUpperCase();
  byId("avatar").title = name(state.me);
  renderBranches();
  byId("count").textContent = state.proposals.length;
  const items = state.proposals.map(proposal => {
    const item = button(proposal.title, () => {
      selected = proposal.id;
      activeTab = "diff";
      render();
    }, "proposal");
    item.setAttribute("aria-current", String(selected === proposal.id));
    const row = element("span", null, "row");
    row.append(element("span", proposal.target + " · " + name(proposal.who), "help"),
      pill(...status(proposal)));
    item.append(row);
    return item;
  });
  byId("list").replaceChildren(...(items.length ? items :
    [element("p", "No branches submitted for review yet.", "help empty-list")]));
  renderDetail();
}

function renderClone() {
  const { integrator, snapshot } = state;
  const checkout = byId("clone-checkout");
  checkout.hidden = !snapshot;
  byId("clone-title").textContent = snapshot ? "Verified snapshot ready"
    : integrator ? "Waiting for the repository" : "Pair with the integrator";
  byId("clone-status").textContent = snapshot
    ? name(integrator) + " signed " + snapshot.branches.length + " protected branches and " +
      snapshot.tags + " tags. PeerTree will check out " + snapshot.default + " in " + state.repo + "."
    : integrator ? "Keep PeerTree open nearby while " + name(integrator) + " publishes the repository snapshot."
      : "Exchange pairing codes with the teammate sharing the repository, then select them as integrator.";
}

function renderBranches() {
  const cards = state.protected.map(branch => {
    const local = state.branches[branch];
    const published = state.shared[branch];
    const card = element("article", null, "branch");
    const label = element("div");
    const info = published && local === published ? "Synced · " + local.slice(0, 9)
      : published ? "Published · " + published.slice(0, 9) +
        (local ? "  /  Local · " + local.slice(0, 9) : "")
      : local ? "Local · " + local.slice(0, 9) : "No local branch";
    label.append(element("div", branch, "branch-name"), element("div", info, "branch-info"));
    card.append(label);
    if (published && published !== local) {
      card.append(button("Sync " + branch, () => change("sync", { branch })));
    }
    if (state.integrator === state.me && local && published !== local) {
      card.append(button("Publish tips", () => change("publish", {})));
    }
    return card;
  });
  byId("branches").replaceChildren(...cards);
}

function renderDetail() {
  const container = byId("detail");
  const proposal = state.proposals.find(item => item.id === selected);
  const version = ++diffVersion;
  if (!proposal) {
    const empty = element("div", null, "empty-detail");
    empty.append(element("h2", "Review a branch together"),
      element("p", "Submit a local branch for review or import a teammate’s exchange.", "help"));
    container.replaceChildren(empty);
    return;
  }

  const heading = element("div", null, "detail-header");
  const meta = element("div", null, "row");
  meta.append(pill(...status(proposal)), element("span", name(proposal.who), "help"),
    element("span", proposal.approvals + "/2 approvals", "help"));
  heading.append(meta, element("h2", proposal.title),
    element("code", proposal.source + " → " + proposal.target + "  ·  " + proposal.head.slice(0, 9), "help"));

  const tabs = element("div", null, "tabs");
  for (const [id, label] of [["diff", "Changes"], ["check", "Pipeline"], ["reviews", "Reviews"]]) {
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
  container.replaceChildren(heading, tabs, body);

  if (activeTab === "diff") {
    body.append(element("p", "Loading diff…", "help"));
    api("diff/" + proposal.id).then(diff => {
      if (version !== diffVersion) return;
      const patch = element("pre", null, "patch");
      const fragment = document.createDocumentFragment();
      for (const line of diff.patch.trimEnd().split("\n")) {
        const type = line.startsWith("@@") ? "hunk"
          : line.startsWith("+") && !line.startsWith("+++") ? "add"
          : line.startsWith("-") && !line.startsWith("---") ? "remove" : "";
        fragment.append(element("span", line || " ", "diff-line " + type));
      }
      patch.append(fragment);
      body.replaceChildren(element("pre", diff.stats || "No file changes."), patch);
      if (diff.truncated) body.append(element("p", "Showing the first 300 KB of the diff.", "help"));
    }).catch(error => {
      if (version === diffVersion) body.replaceChildren(element("p", error.message, "help"));
    });
  }

  if (activeTab === "check") {
    const output = proposal.run;
    const controls = element("div", null, "row");
    controls.append(button("Run local pipeline", () => change("check", { id: proposal.id },
      null, "Running the pipeline for " + proposal.head.slice(0, 9) + "…"), "primary"));
    controls.firstChild.disabled = !state.check;
    if (output) controls.append(pill((output.passed ? "Passed" : "Failed") + " · " + output.secs + "s",
      output.passed ? "ok" : "alert"));
    body.append(controls);
    if (state.check) body.append(element("code", state.check, "help"));
    else body.append(element("p", "Set your pipeline command in Team settings.", "help"));
    if (output) body.append(element("pre", output.output));
  }

  if (activeTab === "reviews") {
    for (const review of proposal.reviews) {
      const item = element("div", null, "review-item");
      const row = element("div", null, "row");
      const approved = review.vote === "approve";
      row.append(element("strong", name(review.who)),
        pill(approved ? "Approved" : "Changes requested", approved ? "ok" : "alert"));
      item.append(row);
      if (review.note) item.append(element("p", review.note, "help"));
      body.append(item);
    }
    if (!proposal.reviews.length) body.append(element("p", "No reviews yet.", "help"));
    if (proposal.who !== state.me && !proposal.merged && !proposal.superseded) {
      const field = element("label", "Review note");
      const note = element("textarea");
      note.maxLength = 1000;
      note.placeholder = "Optional feedback for the author";
      field.append(note);
      const actions = element("div", null, "row");
      const approve = button("Approve revision", () => change("review",
        { id: proposal.id, vote: "approve", note: note.value }), "primary");
      approve.disabled = !proposal.run?.passed || proposal.run.command !== state.check;
      actions.append(approve, button("Request changes", () => change("review",
        { id: proposal.id, vote: "changes", note: note.value })));
      body.append(field, actions);
      if (approve.disabled) body.append(element("p", "Run a successful local pipeline to approve.", "help"));
    }
    if (proposal.ready && !proposal.merged && !proposal.superseded && state.integrator === state.me) {
      body.append(button("Merge into " + proposal.target, () => change("integrate",
        { id: proposal.id }, null, "Merging and publishing branch tips…"), "primary"));
    }
  }
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
}

function setupTeam() {
  byId("public-key").value = state.public;
  byId("key-status").textContent = "";
  byId("check-command").value = state.check;
  const eligible = Object.entries(state.people).filter(([id]) => !state.bootstrap || id !== state.me);
  options(byId("integrator"), eligible, state.integrator, "Choose an integrator");
  byId("reset-pairing-form").hidden = state.paired.length === 0;
  options(byId("reset-pairing"), state.paired.map(id => [id, name(id)]));
  updatePairingCode();
}

function updatePairingCode() {
  byId("peer-invite").hidden = !nearbyPeer?.code;
  const invite = byId("peer-code");
  if (nearbyPeer?.code && invite.value !== nearbyPeer.code) invite.value = nearbyPeer.code;
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
  byId("team-dialog").showModal();
}
byId("team-open").addEventListener("click", openTeam);
byId("clone-pair").addEventListener("click", openTeam);
byId("clone-checkout").addEventListener("click", () => change("checkout", {}, null, "Checking out repository…"));
async function copyFrom(field, status, successMessage) {
  try {
    await navigator.clipboard.writeText(byId(field).value);
    byId(status).textContent = successMessage;
  } catch {
    byId(field).select();
    byId(status).textContent = "Press Command-C to copy the selected text.";
  }
}
byId("copy-key").addEventListener("click", () => copyFrom("public-key", "key-status", "Public key copied."));
byId("copy-peer-code").addEventListener("click", () =>
  copyFrom("peer-code", "peer-code-status", "Pairing code copied."));
byId("new").addEventListener("click", () => perform(async () => {
  await refresh();
  const form = byId("proposal-form");
  const branches = Object.keys(state.branches);
  const current = state.worktrees.find(worktree => worktree.path === state.repo)?.branch;
  options(form.elements.source, branches.map(branch => [branch, branch]),
    current && !state.protected.includes(current) ? current :
      branches.find(branch => !state.protected.includes(branch)));
  options(form.elements.target, state.protected.filter(branch => state.branches[branch])
    .map(branch => [branch, branch]));
  byId("proposal-dialog").showModal();
}));
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
    await change("team", input, () => {
      if (action === "add") event.target.reset();
      event.target.closest("dialog").querySelector(".dialog-error")?.remove();
    });
    if (!document.querySelector(".dialog-error")) setupTeam();
  });
}
refresh().then(checkNearby).catch(error => notify(error.message, true));
setInterval(checkNearby, 4000);
