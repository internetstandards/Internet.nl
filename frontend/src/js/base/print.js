import { validateElements } from "../lib/utils.js";

const elements = {
  details: document.querySelectorAll("details"),
};

function print() {
  if (window.matchMedia) {
    const mediaQueryList = window.matchMedia("print");
    mediaQueryList.addEventListener("change", (mql) => {
      if (mql.matches) {
        if (elements.details.length > 0) {
          elements.details.forEach((el) => {
            el.open = true;
          });
        }
      }
    });
  }
}

if (validateElements(elements, "details")) {
  print();
}

export default print;
