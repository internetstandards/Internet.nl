function startCountDownRetestTime() {
  const countdownTimeEl = document.querySelector(".countdown-time");
  if (countdownTimeEl) {
      const seconds = parseInt(countdownTimeEl.textContent.trim(), 10);
      countDownRetestTime(seconds);
  }
}

function countDownRetestTime(seconds) {
  const linkEl = document.querySelector(".repeat-test.link");
  const countdownEl = document.querySelector(".repeat-test.countdown");
  const countdownTimeEl = document.querySelector(".countdown-time");

  if (linkEl && countdownEl && countdownTimeEl) {

    if (seconds < 1) {
        linkEl.classList.remove("hidden");
        countdownEl.classList.add("hidden");
    } else {
        linkEl.classList.add("hidden");
        countdownEl.classList.remove("hidden");

        countdownTimeEl.textContent = seconds;
        setTimeout(() => countDownRetestTime(seconds - 1), 1000);
    }
  }
}

startCountDownRetestTime();