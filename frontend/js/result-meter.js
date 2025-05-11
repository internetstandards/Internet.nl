const meterElement = document.querySelector('meter');

  if (meterElement) {
  const meterValue = document.querySelector('.meter-value');

  const meterElementValue = Number(meterElement.value);
  meterValue.style.left = `${meterElementValue}%`;
}