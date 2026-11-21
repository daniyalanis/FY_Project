/*
 * KeyGen page controller.
 * The browser sends requests to the existing FastAPI contract; all cryptographic
 * operations remain inside the Python algorithm module.
 */

const state = {
  parameterSet: 512,
  result: null,
};

const byId = (id) => document.getElementById(id);

function appendLog(message, muted = false) {
  const entry = document.createElement("p");
  entry.className = `log-entry${muted ? " muted" : ""}`;

  const timestamp = document.createElement("time");
  timestamp.textContent = new Date().toLocaleTimeString();

  entry.append(timestamp, document.createTextNode(message));
  byId("eventLog").append(entry);
  byId("eventLog").scrollTop = byId("eventLog").scrollHeight;
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
  appendLog("Awaiting request.", true);
});