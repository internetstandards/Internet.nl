import { fetchJson, showProbeFinished, showProbeError } from "../../lib/utils.js";

const summaries = document.querySelectorAll("#probes [aria-busy=true]");

async function runTest() {
  const domain = document.getElementById("conn-test-domain").textContent;
  const ipv6Address = document.getElementById("ipv6-test-addr").textContent;
  const { test_id } = await fetchJson("/connection/gettestid/");

  const urls = [
    `${test_id}.bogus.conn.test-ns-signed.${domain}`,
    `${test_id}.aaaa.conn.test-ns-signed.${domain}`,
    `${test_id}.a.conn.test-ns-signed.${domain}`,
    `${test_id}.a-aaaa.conn.test-ns6-signed.${domain}`,
    `[${ipv6Address}]/connection/addr-test/${test_id}/`,
  ];
  // the test only needs the requests to arrive, failed or not; no-cors because the test hosts send no CORS headers
  await Promise.allSettled(
    urls.map((url) =>
      fetch(`http://${url}`, {
        mode: "no-cors",
        cache: "no-store",
        signal: AbortSignal.timeout(6000),
      })
    )
  );

  await fetchJson(`/connection/finished/${test_id}`);
  return test_id;
}

runTest()
  .then((test_id) => {
    summaries.forEach(showProbeFinished);
    window.location = `/connection/${test_id}/results`;
  })
  .catch((error) => {
    console.error(error);
    summaries.forEach(showProbeError);
  });
