import { fetchJson, showProbeFinished, showProbeError } from "../../lib/utils.js";

const probes = document.getElementById("probes");
let running = probes.children.length;
let failed = false;

function finish(summary, success) {
  if (success) {
    showProbeFinished(summary);
  } else {
    failed = true;
    showProbeError(summary);
  }
  running--;
  if (running === 0 && !failed) {
    window.location = "results";
  }
}

function failRunning() {
  probes.querySelectorAll("[aria-busy=true]").forEach((summary) => finish(summary, false));
}

async function poll(retries) {
  if (retries < 0) {
    failRunning();
    return;
  }

  try {
    // unique url for each poll, so page caches do not return an earlier status
    const statuses = await fetchJson(`${probes.dataset.url}?${Date.now()}`);
    let pending = false;
    for (const { name, done, success } of statuses) {
      const summary = document.getElementById(`${name}-summary`);
      if (!done) {
        pending = true;
      } else if (summary.getAttribute("aria-busy") === "true") {
        finish(summary, success);
      }
    }
    if (pending) {
      setTimeout(() => poll(retries - 1), Number(probes.dataset.timeout));
    }
  } catch (error) {
    console.error(error);
    failRunning();
  }
}

poll(Number(probes.dataset.retries));
