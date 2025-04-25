const cards = document.querySelectorAll(".card:nth-child(n+6)");
const loadMoreBtn = document.getElementById("load-more");
let visibleCount = 0;
const batchSize = 3;

if (loadMoreBtn) {
  loadMoreBtn.addEventListener("click", function () {
    for (let i = visibleCount; i < visibleCount + batchSize; i++) {
      if (cards[i]) {
        cards[i].classList.add('visible');
      }
    }
    visibleCount += batchSize;

    if (visibleCount >= cards.length) {
      loadMoreBtn.classList.add('hidden');
    }
  });
}