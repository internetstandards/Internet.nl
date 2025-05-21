import { validateElements } from "../../lib/utils.js";

// TODO: add languages in aria-label

const elements = {
  carousel: document.querySelector(".knowledge-list"),
  dots: document.querySelectorAll(".dot"),
  items: document.querySelectorAll(".knowledge-list li"),
};

function carousel() {
  const { carousel, dots, items } = elements;

  carousel.addEventListener(
    "scroll",
    () => {
      const index = [...items].findIndex((item) => {
        const rect = item.getBoundingClientRect();
        return rect.left >= 0 && rect.left < window.innerWidth / 2;
      });
      dots.forEach((dot) => dot.classList.remove("active"));
      if (index !== -1) dots[index].classList.add("active");
    },
    { passive: true }
  );

  dots.forEach((dot, index) => {
    const headerId = items[index].querySelector("h3").id;
    const headerText = document.getElementById(headerId).textContent;
    const button = dot.querySelector("button");

    button.setAttribute("aria-label", `Scroll naar ${headerText}`);
    button.addEventListener("click", () => {
      items[index].scrollIntoView({
        behavior: "smooth",
        inline: "center",
        block: "nearest",
      });
    });
  });
}

if (!CSS.supports("selector(::scroll-marker)")) {
  if (validateElements(elements, "carrousel")) {
    carousel();
  }
}

export default carousel;
