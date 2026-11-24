const form = document.querySelector("form");
const folder = document.querySelector("#folder");
const project = document.querySelector("#project");
const peer = document.querySelector("#peer");
const status = document.querySelector("#status");
const openButton = document.querySelector("#open");
const chooseButton = document.querySelector("#choose");
const invoke = window.__TAURI__.core.invoke;
let working = false;

function cloning() {
  return form.elements.mode.value === "clone";
}

function updateMode() {
  const clone = cloning();
  document.querySelector("#clone-fields").hidden = !clone;
  project.required = clone;
  openButton.textContent = clone ? "Start clone" : "Open worktree";
}

function showStatus(message, error = false) {
  status.hidden = !message;
  status.textContent = message;
  status.classList.toggle("error", error);
}

function lockControls(locked) {
  working = locked;
  for (const control of form.elements) control.disabled = locked;
}

async function openWorkspace() {
  if (working || !form.reportValidity()) return;
  const settings = {
    folder: folder.value,
    cloneProject: cloning() ? project.value.trim() : null,
    enablePeer: peer.checked,
  };
  lockControls(true);
  showStatus("Opening workspace…");
  try {
    await invoke("open_workspace", settings);
    showStatus("");
  } catch (error) {
    showStatus(String(error), true);
  } finally {
    lockControls(false);
  }
}

for (const input of form.elements.mode) {
  input.addEventListener("change", () => {
    if (cloning()) peer.checked = true;
    updateMode();
  });
}

chooseButton.addEventListener("click", async () => {
  if (working) return;
  const clone = cloning();
  lockControls(true);
  try {
    const selected = await invoke("choose_folder", { clone });
    if (selected !== null) {
      folder.value = selected;
      if (clone && !project.value) project.value = selected.split("/").filter(Boolean).at(-1) || "";
    }
  } catch (error) {
    showStatus(String(error), true);
  } finally {
    lockControls(false);
  }
});

form.addEventListener("submit", event => {
  event.preventDefault();
  openWorkspace();
});

updateMode();
invoke("initial_workspace").then(workspace => {
  if (workspace) {
    [folder.value, peer.checked] = workspace;
    return openWorkspace();
  }
}).catch(error => showStatus(String(error), true));
