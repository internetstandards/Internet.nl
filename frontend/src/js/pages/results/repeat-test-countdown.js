import {
  validateElements,
  validateNumber,
  toggleElements,
} from "../../lib/utils.js";

const elements = {
  retestTime: document.querySelector(".countdown-time"),
};

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
    text: document.querySelector(".repeat-test.link"),
    link: document.querySelector(".repeat-test.countdown"),
    time: document.querySelector(".countdown-time"),
  };

  if (!validateElements(elements)) return;

  if (seconds < 1) {
    toggleElements(".repeat-test.link", false);
    toggleElements(".repeat-test.countdown", true);
  } else {
    toggleElements(".repeat-test.link", true);
    toggleElements(".repeat-test.countdown", false);
    elements.time.textContent = seconds;
    setTimeout(() => countDownRetestTime(seconds - 1), 1000);
  }
}

if (validateElements(elements, "results")) {
  startCountDownRetestTime();
}

export default startCountDownRetestTime;
