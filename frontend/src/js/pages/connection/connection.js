import {
  validateElements,
  toggleElements,
  fetchJson,
} from "../../lib/utils.js";

// State management
const state = {
  completedTests: 0,
  requiredTests: 5,
  timeout: 6000, // milliseconds
};

/**
 * Enable results and redirect to the results page
 */
function enableResults() {
  const elements = {
    continue: document.querySelector("#continue"),
  };

  if (!validateElements(elements)) return;
  window.location = elements.continue.getAttribute("href");
}

/**
 * Show results for a specific category
 * @param {string} category - The category to show results for
 * @param {Object} results - The results object
 */
function showResults(category, results) {
  if (!results) return;

  const elements = {
    probeFinished: document.querySelector("#probe-finished")?.textContent,
    summary: document.querySelector(`#${category}-summary`),
  };

  if (!validateElements(elements, category)) return;

  elements.summary.setAttribute("aria-busy", "false");
  elements.summary.textContent = elements.probeFinished;
}

/**
 * Handle test completion callback
 * @param {string} test_id - The test ID
 */
async function handleTestCompletion(test_id) {
  state.completedTests++;

  if (state.completedTests >= state.requiredTests) {
    try {
      const { connipv6, connresolver } = await fetchJson(
        `/connection/finished/${test_id}`
      );

      showResults("ipv6", connipv6);
      showResults("resolver", connresolver);
      enableResults();
    } catch (error) {
      console.error("Error fetching test results:", error);
    }
  }
}

/**
 * Fetch test data from a URL
 * @param {string} url - The URL to fetch from
 * @param {string} test_id - The test ID
 */
async function fetchTest(url, test_id) {
  try {
    const controller = new AbortController();
    const request = new Request(`http://${url}`, {
      method: "get",
      signal: controller.signal,
    });

    await fetch(request);
  } catch (error) {
    if (error.name === "TimeoutError") {
      console.error(
        `Timeout: It took more than ${
          state.timeout / 1000
        } seconds to get the result for ${test_id}!`
      );
    } else if (error.name === "AbortError") {
      console.error("Fetch aborted by the user");
    } else if (error.name === "TypeError") {
      console.error("AbortSignal.timeout() method is not supported");
    } else {
      // A network error, or some other problem.
      console.error(`Error: type: ${error.name}, message: ${error.message}`);
    }
  } finally {
    await handleTestCompletion(test_id);
  }
}

/**
 * Start the connection test
 * @param {string} test_id - The test ID
 */
function startConnectionTest(test_id) {
  const elements = {
    connTestDomain: document.querySelector("#conn-test-domain")?.textContent,
    ipv6TestAddr: document.querySelector("#ipv6-test-addr")?.textContent,
  };

  if (!validateElements(elements)) return;

  const testUrls = [
    `${test_id}.bogus.conn.test-ns-signed.${elements.connTestDomain}`,
    `${test_id}.aaaa.conn.test-ns-signed.${elements.connTestDomain}`,
    `${test_id}.a.conn.test-ns-signed.${elements.connTestDomain}`,
    `${test_id}.a-aaaa.conn.test-ns6-signed.${elements.connTestDomain}`,
    `[${elements.ipv6TestAddr}]/connection/addr-test/${test_id}/`,
  ];

  testUrls.forEach((url) => fetchTest(url, test_id));
}

/**
 * Initialize and start the connection test
 */
async function initializeConnectionTest() {
  state.completedTests = 0;

  // Show probing text
  toggleElements(".probing-text", false);

  try {
    const { test_id } = await fetchJson("/connection/gettestid/");

    startConnectionTest(test_id);

    const elements = {
      connForward: document.querySelector(".connforward"),
    };

    if (!validateElements(elements)) return;

    elements.connForward.setAttribute("href", `/connection/${test_id}/results`);
  } catch (error) {
    console.error("Error initializing connection test:", error);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initializeConnectionTest();
});
