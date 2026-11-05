const time = document.querySelector(".countdown-time");

function countDown(seconds) {
  if (seconds < 1) {
    document.querySelector(".repeat-test.link").classList.remove("hidden");
    document.querySelector(".repeat-test.countdown").classList.add("hidden");
  } else {
    time.textContent = seconds;
    setTimeout(() => countDown(seconds - 1), 1000);
  }
}

// connection test results have no retest
if (time) {
  countDown(Number(time.textContent));
}
