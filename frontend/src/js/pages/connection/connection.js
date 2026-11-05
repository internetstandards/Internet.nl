import {
  validateElements,
  fetchJson,
  fetchWithTimeout,
} from "../../lib/utils.js";

// State management
const state = {
  completedTests: 0,
  requiredTests: 5,
  timeout: 6000, // milliseconds
};

/**
 * Redirect to the results page
 * @param {string} test_id - The test ID
 */
function enableResults(test_id) {
  window.location = `/connection/${test_id}/results`;
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
        await fetch(`/connection/finished/${test_id}`)
      );

      showResults("ipv6", connipv6);
      showResults("resolver", connresolver);
      enableResults(test_id);
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
    // only the request matters to the test, the test hosts do not send CORS headers
    await fetchWithTimeout(`http://${url}`, state.timeout, {
      mode: "no-cors",
      cache: "no-store",
    });
  } catch (error) {
    console.error(`Connection test request to ${url} failed: ${error.name}`);
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

  try {
    const { test_id } = await fetchJson(await fetch("/connection/gettestid/"));

    startConnectionTest(test_id);
  } catch (error) {
    console.error("Error initializing connection test:", error);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initializeConnectionTest();
});
