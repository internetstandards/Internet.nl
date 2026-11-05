async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`);
  }
  return response.json();
}

function showProbeFinished(summary) {
  summary.setAttribute("aria-busy", "false");
  summary.textContent = document.getElementById("probe-finished").textContent;
  summary.classList.add("done");
}

function showProbeError(summary) {
  summary.setAttribute("aria-busy", "false");
  summary.innerHTML = document.getElementById("probe-error-summary").innerHTML;
  summary.closest("li").classList.replace("probing", "error");
  // do not go on to the results, because they would be incomplete
  document.getElementById("probes-no-redirection").hidden = false;
}

export { fetchJson, showProbeFinished, showProbeError };
