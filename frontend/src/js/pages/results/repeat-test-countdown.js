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
  if (!validateElements(elements)) {
    console.error("Could not find countdown time element");
    return;
  }

  const seconds = validateNumber(
    elements.retestTime.textContent,
    "retest time"
  );

  if (seconds === null) {
    console.error("Invalid retest time value");
    return;
  }

  console.log("Starting countdown with", seconds, "seconds");
  countDownRetestTime(seconds);
}

/**
 * Count down the retest timer
 * @param {number} seconds - Remaining seconds
 */
function countDownRetestTime(seconds) {
  const elements = {
    link: document.querySelector(".repeat-test.link"),
    countdown: document.querySelector(".repeat-test.countdown"),
    time: document.querySelector(".countdown-time"),
  };

  if (!validateElements(elements)) {
    console.error("Could not find required elements for countdown");
    return;
  }

  console.log("Countdown:", seconds, "seconds remaining");

  if (seconds < 1) {
    console.log("Countdown finished, showing link");
    elements.link.classList.remove("hidden");
    elements.countdown.classList.add("hidden");
  } else {
    console.log("Countdown running, showing countdown");
    elements.link.classList.add("hidden");
    elements.countdown.classList.remove("hidden");
    elements.time.textContent = seconds;
    setTimeout(() => countDownRetestTime(seconds - 1), 1000);
  }
}

if (validateElements(elements, "results")) {
  startCountDownRetestTime();
}

export default startCountDownRetestTime;
