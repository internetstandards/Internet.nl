// without ::details-content, CSS cannot keep the follow-up details open on wide screens
if (!CSS.supports("selector(::details-content)")) {
  const details = document.querySelector(".action-card details");
  const wide = window.matchMedia("(min-width: 56.25rem)");
  const update = () => details.toggleAttribute("open", wide.matches);
  update();
  wide.addEventListener("change", update);
}
