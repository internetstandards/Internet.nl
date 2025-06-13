import { validateElements } from "../lib/utils.js";

const elements = {
  languageForm: document.querySelector(".language-form"),
  languageSelect: document.getElementById("language-select"),
};

function languageSwitch() {
  elements.languageSelect.addEventListener("change", function () {
    elements.languageForm.submit();
  });
}

if (validateElements(elements, "language-switch")) {
  languageSwitch();
}

export default languageSwitch;
