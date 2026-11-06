// show or hide all subtests of a category at once
document.querySelectorAll(".result-details-item").forEach((category) => {
  const button = category.querySelector(".open-all");
  const subtests = [...category.querySelectorAll(".result-details-content details")];

  function update() {
    const allOpen = subtests.every((details) => details.open);
    button.textContent = allOpen ? button.dataset.hide : button.dataset.show;
  }

  button.addEventListener("click", () => {
    const open = !subtests.every((details) => details.open);
    subtests.forEach((details) => {
      details.open = open;
    });
    update();
  });
  // keep the text right when subtests are opened one by one; toggle does not bubble
  category.addEventListener("toggle", update, true);
  update();
});
