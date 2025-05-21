/**
 * Check if required DOM elements exist
 * @param {Object} elements - Object containing element queries
 * @param {string} context - Context for error message
 * @returns {boolean} Whether all required elements exist
 */
function validateElements(elements, context = "") {
  const missingElements = Object.entries(elements)
    .filter(([_, element]) => !element)
    .map(([name]) => name);

  if (missingElements.length > 0) {
    console.error(
      `Required elements not found${context ? ` for ${context}` : ""}:`,
      missingElements.join(", ")
    );
    return false;
  }
  return true;
}

/**
 * Validate and parse a numeric value
 * @param {string} value - Value to parse
 * @param {string} name - Name of the value for error message
 * @returns {number|null} Parsed number or null if invalid
 */
function validateNumber(value, name) {
  const num = parseInt(value);
  if (isNaN(num)) {
    console.error(`Invalid ${name} value:`, value);
    return null;
  }
  return num;
}

/**
 * Toggle visibility of elements
 * @param {string} selector - CSS selector for elements
 * @param {boolean} hide - Whether to hide or show elements
 * @param {string} context - Context for error message
 */
function toggleElements(selector, hide, context = "") {
  const elements = document.querySelectorAll(selector);

  if (!validateElements(elements, context)) return;

  elements.forEach((element) => {
    element.classList.toggle("hidethis", hide);
    element.setAttribute("aria-hidden", hide.toString());
  });
}

/**
 * Handle HTTP response
 * @param {Response} response - Fetch response object
 * @returns {Object} Parsed JSON response
 */
async function fetchJson(response) {
  try {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error fetching JSON:", error);
    throw error;
  }
}

/**
 * Fetch data with timeout
 * @param {string} url - URL to fetch
 * @param {number} timeout - Timeout in milliseconds
 * @param {Object} options - Additional fetch options
 * @returns {Promise<Response>} Fetch response
 */
async function fetchWithTimeout(url, timeout, options = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(timeout),
    });
    return response;
  } catch (error) {
    throw error;
  }
}

/**
 * Hide elements for users without JavaScript
 */
function hideJSLess() {
  toggleElements(".jsless", true);
}

export {
  validateElements,
  validateNumber,
  toggleElements,
  fetchJson,
  fetchWithTimeout,
  hideJSLess,
};
