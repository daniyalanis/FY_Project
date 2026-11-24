/*
 * KeyGen page controller.
 * The browser sends requests to the existing FastAPI contract; all cryptographic
 * operations remain inside the Python algorithm module.
 */

const state = {
  parameterSet: 512,
  result: null,
  encap: null,
  decap: null,
};

const uploadedArtifacts = new Map();

const byId = (id) => document.getElementById(id);

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function activeSource(group) {
  return document.querySelector(`input[name="${group}-source"]:checked`).value;
}

function refreshSource(group) {
  const source = activeSource(group);
  ["paste", "upload"].forEach((kind) => {
    const field = document.querySelector(`[data-source-panel="${group}-${kind}"]`);
    field.hidden = source !== kind;
  });
}

function artifactHex(group) {
  const source = activeSource(group);
  const value = source === "generated"
    ? { "encap-ek": state.result?.ek_hex, "decap-dk": state.result?.dk_hex, "decap-ct": state.encap?.ct_hex }[group]
    : source === "paste"
      ? document.querySelector(`[data-source-panel="${group}-paste"]`).value
      : uploadedArtifacts.get(group);

  if (!value) throw new Error(`Select or provide a ${group.replaceAll("-", " ")}.`);
  const hex = value.replace(/\s+/g, "");
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2) throw new Error(`${group.replaceAll("-", " ")} must be valid hexadecimal.`);
  return hex;
}

function setStatus(id, message) {
  byId(id).textContent = message;
}

document.querySelectorAll('input[type="radio"][name$="-source"]').forEach((radio) => {
  radio.addEventListener("change", () => refreshSource(radio.name.replace(/-source$/, "")));
});

document.querySelectorAll(".artifact-upload").forEach((input) => {
  input.addEventListener("change", async () => {
    const group = { encapEkUpload: "encap-ek", decapDkUpload: "decap-dk", decapCtUpload: "decap-ct" }[input.id];
    const file = input.files?.[0];
    if (!file) return;
    uploadedArtifacts.set(group, bytesToHex(await file.arrayBuffer()));
    setStatus(group === "encap-ek" ? "encapEkStatus" : group === "decap-dk" ? "decapDkStatus" : "decapCtStatus", `${file.name} · ${file.size} bytes loaded.`);
  });
});

["encap-ek", "decap-dk", "decap-ct"].forEach(refreshSource);

function appendLog(message, muted = false) {
  const entry = document.createElement("p");
  entry.className = `log-entry${muted ? " muted" : ""}`;

  const timestamp = document.createElement("time");
  timestamp.textContent = new Date().toLocaleTimeString();

  entry.append(timestamp, document.createTextNode(message));
  byId("eventLog").append(entry);
  byId("eventLog").scrollTop = byId("eventLog").scrollHeight;
}

function appendOperationLog(logId, message, muted = false) {
  const entry = document.createElement("p");
  entry.className = `log-entry${muted ? " muted" : ""}`;
  const timestamp = document.createElement("time");
  timestamp.textContent = new Date().toLocaleTimeString();
  entry.append(timestamp, document.createTextNode(message));
  const log = byId(logId);
  log.append(entry);
  log.scrollTop = log.scrollHeight;
}

function resetOperationLog(logId) {
  byId(logId).replaceChildren();
}

function currentMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

function normaliseSeed(value, label) {
  const seed = value.trim().replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]{64}$/.test(seed)) {
    throw new Error(`${label} must be exactly 64 hexadecimal characters.`);
  }
  return seed;
}

function fillDeterministicSeeds() {
  byId("seedD").value = window.crypto.getRandomValues(new Uint8Array(32)).reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
  byId("seedZ").value = window.crypto.getRandomValues(new Uint8Array(32)).reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
}

byId("fillDet").addEventListener("click", fillDeterministicSeeds);

/* Parameter-set selector. */
document.querySelectorAll("[data-parameter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.parameterSet = Number(button.dataset.parameter);

    document.querySelectorAll("[data-parameter]").forEach((option) => {
      const selected = option === button;
      option.classList.toggle("active", selected);
      option.setAttribute("aria-pressed", String(selected));
    });
  });
});

/* Reveal seed fields only for deterministic test runs. */
document.querySelectorAll('input[name="mode"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    byId("seedFields").hidden = currentMode() !== "deterministic";
  });
});

/* Submit a key-generation request using the established API schema. */
byId("runButton").addEventListener("click", async () => {
  byId("errorMessage").textContent = "";
  byId("resultsSection").hidden = true;
  byId("eventLog").replaceChildren();

  const mode = currentMode();
  const payload = {
    parameter_set: state.parameterSet,
    mode,
  };

  try {
    if (mode === "deterministic") {
      payload.d_hex = normaliseSeed(byId("seedD").value, "Seed D");
      payload.z_hex = normaliseSeed(byId("seedZ").value, "Seed Z");
    }
  } catch (error) {
    byId("errorMessage").textContent = error.message;
    return;
  }

  appendLog(`Request accepted · ML-KEM-${state.parameterSet}.`);
  appendLog(`Randomness mode · ${mode}.`);
  appendLog("Calling ML_KEM_KeyGen().");

  try {
    const response = await fetch("/api/keygen/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = await response.json();
    if (!response.ok) {
      throw new Error(
        typeof body.detail === "string" ? body.detail : "Key generation request failed."
      );
    }

    state.result = body;

    appendLog("Key pair generated.");
    appendLog(`ek · ${body.outputs.ek.size_bytes} bytes.`);
    appendLog(`dk · ${body.outputs.dk.size_bytes} bytes.`);

    byId("executionMeta").hidden = false;
    byId("executionMeta").textContent =
      `ID ${body.execution_id}  /  ${body.execution_time_seconds}s  /  ML-KEM-${body.parameter_set}`;

    byId("ekSize").textContent = `${body.outputs.ek.size_bytes} B`;
    byId("dkSize").textContent = `${body.outputs.dk.size_bytes} B`;
    byId("ekPreview").textContent = `${body.ek_hex.slice(0, 256)}…`;
    byId("dkPreview").textContent = `${body.dk_hex.slice(0, 256)}…`;
    byId("ekDownload").href = body.outputs.ek.download_url;
    byId("dkDownload").href = body.outputs.dk.download_url;
    setStatus("encapEkStatus", `Generated ek · ${body.outputs.ek.size_bytes} bytes.`);
    setStatus("decapDkStatus", `Generated dk · ${body.outputs.dk.size_bytes} bytes.`);

    byId("resultsSection").hidden = false;
  } catch (error) {
    appendLog(`ERROR · ${error.message}`);
    byId("errorMessage").textContent = error.message;
  } finally {
  }
});

/* Copy the complete hexadecimal key returned by the API. */
document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!state.result) return;

    const hex = button.dataset.copy === "ek"
      ? state.result.ek_hex
      : state.result.dk_hex;

    try {
      await navigator.clipboard.writeText(hex);
      const originalLabel = button.textContent;
      button.textContent = "COPIED";
      window.setTimeout(() => { button.textContent = originalLabel; }, 1000);
    } catch {
      byId("errorMessage").textContent = "Clipboard access is unavailable in this browser context.";
    }
  });
});

/* Return the page to its initial state without changing the selected parameter set. */
byId("resetButton").addEventListener("click", () => {
  byId("seedD").value = "";
  byId("seedZ").value = "";
  document.querySelector('input[name="mode"][value="random"]').checked = true;
  byId("seedFields").hidden = true;
  byId("resultsSection").hidden = true;
  byId("executionMeta").hidden = true;
  byId("errorMessage").textContent = "";
  byId("eventLog").replaceChildren();

  state.result = null;
  state.encap = null;
  state.decap = null;
  uploadedArtifacts.clear();
  setStatus("encapEkStatus", "Generate a key pair above to use its encapsulation key.");
  setStatus("decapDkStatus", "Generate a key pair above to use its decapsulation key.");
  setStatus("decapCtStatus", "Run encapsulation above to use its ciphertext.");
  byId("encapOutput").hidden = true;
  byId("decapOutput").hidden = true;
  resetOperationLog("encapEventLog");
  resetOperationLog("decapEventLog");
  appendOperationLog("encapEventLog", "Awaiting request.", true);
  appendOperationLog("decapEventLog", "Awaiting request.", true);
  appendLog("Awaiting request.", true);
});

byId("encapButton").addEventListener("click", async () => {
  byId("encapError").textContent = "";
  byId("encapOutput").hidden = true;
  resetOperationLog("encapEventLog");
  try {
    const ekHex = artifactHex("encap-ek");
    appendOperationLog("encapEventLog", `Request accepted · ML-KEM-${state.parameterSet}.`);
    appendOperationLog("encapEventLog", "Calling ML_KEM_Encaps().");
    const response = await fetch("/api/operations/encapsulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ parameter_set: state.parameterSet, ek_hex: ekHex }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Encapsulation failed.");
    state.encap = body;
    byId("ctSize").textContent = `${body.outputs.ct.size_bytes} B`;
    byId("ctPreview").textContent = `${body.ct_hex.slice(0, 256)}…`;
    byId("ctDownload").href = body.outputs.ct.download_url;
    byId("encapSecretSize").textContent = `${body.outputs.shared_secret.size_bytes} B`;
    byId("encapSecretPreview").textContent = body.shared_secret_hex;
    byId("encapSecretDownload").href = body.outputs.shared_secret.download_url;
    setStatus("decapCtStatus", `Generated c · ${body.outputs.ct.size_bytes} bytes.`);
    byId("encapOutput").hidden = false;
    appendOperationLog("encapEventLog", "Encapsulation completed.");
    appendOperationLog("encapEventLog", `c · ${body.outputs.ct.size_bytes} bytes.`);
    appendOperationLog("encapEventLog", `K · ${body.outputs.shared_secret.size_bytes} bytes.`);
  } catch (error) {
    appendOperationLog("encapEventLog", `ERROR · ${error.message}`);
    byId("encapError").textContent = error.message;
  }
});

byId("decapButton").addEventListener("click", async () => {
  byId("decapError").textContent = "";
  byId("decapOutput").hidden = true;
  resetOperationLog("decapEventLog");
  try {
    const payload = {
      parameter_set: state.parameterSet,
      dk_hex: artifactHex("decap-dk"),
      ct_hex: artifactHex("decap-ct"),
      expected_shared_secret_hex: state.encap?.shared_secret_hex,
    };
    appendOperationLog("decapEventLog", `Request accepted · ML-KEM-${state.parameterSet}.`);
    appendOperationLog("decapEventLog", "Calling ML_KEM_Decaps().");
    const response = await fetch("/api/operations/decapsulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Decapsulation failed.");
    state.decap = body;
    byId("decapSecretSize").textContent = `${body.outputs.shared_secret.size_bytes} B`;
    byId("decapSecretPreview").textContent = body.shared_secret_hex;
    byId("decapDownload").href = body.outputs.shared_secret.download_url;
    const matchStatus = byId("matchStatus");
    matchStatus.className = `match-status ${body.matches_encapsulation ? "match" : body.matches_encapsulation === false ? "mismatch" : ""}`;
    matchStatus.textContent = body.matches_encapsulation === null
      ? "No encapsulation secret supplied for comparison."
      : body.matches_encapsulation ? "MATCH — shared secrets are identical." : "MISMATCH — shared secrets differ.";
    byId("decapOutput").hidden = false;
    appendOperationLog("decapEventLog", body.matches_encapsulation === false ? "Decapsulation completed with a mismatch." : "Decapsulation completed.");
    appendOperationLog("decapEventLog", `K' · ${body.outputs.shared_secret.size_bytes} bytes.`);
  } catch (error) {
    appendOperationLog("decapEventLog", `ERROR · ${error.message}`);
    byId("decapError").textContent = error.message;
  }
});

document.querySelectorAll("[data-operation-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = button.dataset.operationCopy === "ct"
      ? state.encap?.ct_hex
      : button.dataset.operationCopy === "encap-secret"
        ? state.encap?.shared_secret_hex
        : state.decap?.shared_secret_hex;
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      const originalLabel = button.textContent;
      button.textContent = "COPIED";
      window.setTimeout(() => { button.textContent = originalLabel; }, 1000);
    } catch {
      byId("encapError").textContent = "Clipboard access is unavailable in this browser context.";
    }
  });
});
