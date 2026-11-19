const button = document.getElementById("copy-link");

function showFailed(link) {
  alert(`${button.dataset.copyFailed} ${link}`);
}

function copy(link) {
  navigator.clipboard.writeText(link).then(() => {
    button.classList.add("copied");
    setTimeout(() => button.classList.remove("copied"), 5000);
  }, () => showFailed(link));
}

button.addEventListener("click", () => {
  const link = window.location.href;
  if (!window.isSecureContext) {
    showFailed(link);
  } else if (navigator.share) {
    // AbortError is the user closing the share dialog
    navigator.share({ url: link }).catch((error) => {
      if (error.name !== "AbortError") {
        copy(link);
      }
    });
  } else {
    copy(link);
  }
});
