function updateArrow() {
  const meterValue = document.querySelector('.meter-value');
  const meterElement = document.querySelector('meter');

  const meterElementValue = Number(meterElement.value);

  meterValue.style.left = `${meterElementValue}%`;
};

updateArrow();