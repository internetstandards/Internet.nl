import { validateElements } from "../../lib/utils.js";

const elements = {
  meterElement: document.querySelector("meter"),
  meterValue: document.querySelector(".meter-value"),
};

function resultMeter() {
  const meterElementValue = Number(elements.meterElement.value);
  elements.meterValue.style.left = `${meterElementValue}%`;
}

if (validateElements(elements, "result-meter")) {
  resultMeter();
}

export default resultMeter;
