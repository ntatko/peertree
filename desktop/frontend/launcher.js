const form = document.querySelector("form");
const folder = document.querySelector("#folder");
const peer = document.querySelector("#peer");
const status = document.querySelector("#status");
const openButton = document.querySelector("#open");
const chooseButton = document.querySelector("#choose");
const invoke = window.__TAURI__.core.invoke;
let working = false;

function joining() {
  return form.elements.mode.value === "join";
}

function updateMode() {
  const join = joining();
  document.querySelector("#open-fields").hidden = join;
  document.querySelector("#join-help").hidden = !join;
  folder.required = !join;
  openButton.textContent = join ? "Join" : "Open worktree";
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
    folder: joining() ? "" : folder.value,
    join: joining(),
    enablePeer: joining() || peer.checked,
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
  input.addEventListener("change", updateMode);
}

chooseButton.addEventListener("click", async () => {
  if (working) return;
  lockControls(true);
  try {
    const selected = await invoke("choose_folder");
    if (selected !== null) folder.value = selected;
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
