// open the subtest named in the URL, and put a subtest's id in the URL when it is opened
function openLinked() {
  const details = document.getElementById(location.hash.slice(1));
  if (details?.tagName === "DETAILS") {
    details.open = true;
  }
}

openLinked();
window.addEventListener("hashchange", openLinked);

// listen for clicks, not toggle: opening all subtests and printing also fire toggle
document.querySelectorAll(".result-details-content details[id] > summary").forEach((summary) => {
  summary.addEventListener("click", () => {
    if (!summary.parentElement.open) {
      history.replaceState(null, "", `#${summary.parentElement.id}`);
    }
  });
});
