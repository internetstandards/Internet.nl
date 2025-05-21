import {
  validateElements,
  validateNumber,
  toggleElements,
} from "../../lib/utils.js";

/**
 * Start the countdown timer for retesting
 */
function startCountDownRetestTime() {
  if (!validateElements(elements)) return;

  const seconds = validateNumber(
    elements.retestTime.textContent,
    "retest time"
  );

  if (seconds === null) return;

  countDownRetestTime(seconds);
}

/**
 * Count down the retest timer
 * @param {number} seconds - Remaining seconds
 */
function countDownRetestTime(seconds) {
  const elements = {
    text: document.querySelector(".retest-text"),
    link: document.querySelector(".retest-link"),
    time: document.querySelector(".retest-text .retest-time"),
  };

  if (!validateElements(elements)) return;

  if (seconds < 1) {
    toggleElements(".retest-text", true);
    toggleElements(".retest-link", false);
  } else {
    toggleElements(".retest-text", false);
    toggleElements(".retest-link", true);
    elements.time.textContent = seconds;
    setTimeout(() => countDownRetestTime(seconds - 1), 1000);
  }
}

const elements = {
  retestTime: document.querySelector("#retest-time"),
};

if (validateElements(elements, "results")) {
  startCountDownRetestTime();
}
