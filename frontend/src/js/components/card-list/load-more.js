import { validateElements, toggleElements } from "../../lib/utils.js";

const elements = {
  cards: document.querySelectorAll(".card:nth-child(n+6)"),
  loadMoreBtn: document.getElementById("load-more"),
};

function loadMore() {
  let visibleCount = 0;
  const batchSize = 3;

  const { cards, loadMoreBtn } = elements;

  loadMoreBtn.addEventListener("click", function () {
    for (let i = visibleCount; i < visibleCount + batchSize; i++) {
      if (cards[i]) {
        cards[i].classList.add("visible");
      }
    }
    visibleCount += batchSize;

    if (visibleCount >= cards.length) {
      loadMoreBtn.classList.add('hidden');
    }
  });
}

if (validateElements(elements, "load-more")) {
  loadMore();
}

export default loadMore;
