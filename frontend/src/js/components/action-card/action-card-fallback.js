import { validateElements } from "../../lib/utils.js";

const elements = {
  details: document.querySelector(".action-card details"),
};

function actionCardFallback() {
  const toggleDetailsOpen = () => {
    if (window.innerWidth > 900) {
      elements.details.setAttribute("open", "");
    } else {
      elements.details.removeAttribute("open");
    }
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
