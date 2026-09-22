import {
  validateElements,
  validateNumber,
  toggleElements,
  fetchJson,
} from "../../lib/utils.js";

// State management
const state = {
  probesRunning: 0,
  javascriptRetries: 0,
  javascriptTimeout: 0,
  probesUrl: "",
};

/**
 * Show results for a specific category
 * @param {string} category - The category to show results for
 * @param {Object} results - The results object
 */
function showResults(category, results) {
  const elements = {
    summary: document.querySelector(`#${category}-summary`),
    probeFinished: document.querySelector("#probe-finished")?.textContent,
  };

  if (!validateElements(elements, category)) return;
  if (elements.summary.getAttribute("aria-busy") === "false") return;

  state.probesRunning--;
  if (state.probesRunning <= 0) {
    window.location = "results";
  }

  if (!results) return;

  elements.summary.setAttribute("aria-busy", "false");
  elements.summary.textContent = elements.probeFinished;
  elements.summary.classList.add("done");
}

/**
 * Show error for a specific category
 * @param {string} category - The category to show error for
 */
function showError(category) {
  state.probesRunning--;

  const elements = {
    errorSummary: document.querySelector("#probe-error-summary")?.innerHTML,
    summary: document.querySelector(`#${category}-summary`),
    icon: document.querySelector(`#${category}-icon`),
  };

  if (!validateElements(elements, category)) return;

  // Update probe status
  elements.summary.setAttribute("aria-busy", "false");
  elements.summary.innerHTML = elements.errorSummary;
  elements.icon.setAttribute("src", "/static/probe-error.png");
}

/**
 * Show errors for all running probes
 */
function showErrors() {
  const elements = {
    probes: document.querySelectorAll("#probes > div"),
  };

  if (!validateElements(elements)) return;

  elements.probes.forEach((probe) => {
    const nameElement = probe.querySelector(".probe-name");
    if (!nameElement) {
      console.error("Required element .probe-name not found in probe");
      return;
    }

    const name = nameElement.textContent;
    if (!name) {
      console.error("Probe name is empty");
      return;
    }

    const summaryElement = document.querySelector(`#${name}-summary`);
    if (!summaryElement) {
      console.error(`Required element #${name}-summary not found`);
      return;
    }

    if (summaryElement.getAttribute("aria-busy") === "true") {
      showError(name);
    }
  });
}

/**
 * Parse probe statuses and update UI accordingly
 * @param {Array} json - Array of probe status objects
 * @returns {boolean} Whether to retry polling
 */
function parseStatuses(json) {
  if (!Array.isArray(json)) {
    console.error("Invalid response format: expected array, got", typeof json);
    return false;
  }

  let retry = false;

  json.forEach((obj) => {
    if (!obj.name) {
      console.error("Probe status object missing required 'name' property");
      return;
    }

    if (obj.done) {
      if (obj.success) {
        showResults(obj.name, obj);
      } else {
        showError(obj.name);
      }
    } else {
      retry = true;
    }
  });

  return retry;
}

/**
 * Poll for probe status updates
 * @param {string} testurl - The URL to poll
 * @param {number} retryCount - Number of retries remaining
 */
async function pollProbes(testurl, retryCount) {
  if (typeof retryCount === "undefined") {
    const retriesElement = document.querySelector("#javascript-retries");

    if (!validateElements(retriesElement, "probe")) return;

    retryCount = validateNumber(retriesElement.textContent, "retries");
    if (retryCount === null) return;
  }

  if (retryCount < 0) {
    showErrors();
    return;
  }

  try {
    const json = await fetchJson(await fetch(testurl));

    if (parseStatuses(json)) {
      const timeoutElement = document.querySelector("#javascript-timeout");
      if (!validateElements(timeoutElement, "probe")) return;

      const timeout = validateNumber(timeoutElement.textContent, "timeout");
      if (timeout === null) return;

      setTimeout(() => {
        pollProbes(testurl, retryCount - 1);
      }, timeout);
    }
  } catch (error) {
    console.error("Error polling probes:", error);
    showErrors();
  }
}

function initializeProbe() {
  // Validate numeric values
  const retries = validateNumber(elements.retries.textContent, "retries");
  const timeout = validateNumber(elements.timeout.textContent, "timeout");
  if (retries === null || timeout === null) return;

  // Initialize state
  state.javascriptRetries = retries;
  state.javascriptTimeout = timeout;
  state.probesRunning = elements.probes.length;
  state.probesUrl = elements.url.textContent;

  // Show probing text
  toggleElements(".probing-text", false);

  // Start polling
  pollProbes(state.probesUrl);
}

const elements = {
  retries: document.querySelector("#javascript-retries"),
  timeout: document.querySelector("#javascript-timeout"),
  url: document.querySelector("#probes-url"),
  probes: document.querySelectorAll("#probes > div"),
};

document.addEventListener("DOMContentLoaded", () => {
  if (validateElements(elements, "probe")) {
    initializeProbe();
  }
});
