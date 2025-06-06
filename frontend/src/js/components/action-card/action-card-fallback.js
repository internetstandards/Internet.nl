import { validateElements } from "../../lib/utils.js";

const elements = {
  details: document.querySelector(".action-card details"),
};

function actionCardFallback() {
  const toggleDetailsOpen = () => {
    elements.details.setAttribute("open", window.innerWidth > 900 ? "" : null);
  };

  toggleDetailsOpen();
  window.addEventListener("resize", toggleDetailsOpen, { passive: true });
}

if (!CSS.supports("selector(::details-content)")) {
  if (validateElements(elements, "action-card-fallback")) {
    actionCardFallback();
  }
}

export default actionCardFallback;
