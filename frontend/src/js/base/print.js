window.addEventListener("beforeprint", () => {
  document.querySelectorAll("details").forEach((details) => {
    // details with a name open one at a time
    details.removeAttribute("name");
    details.open = true;
  });
});
