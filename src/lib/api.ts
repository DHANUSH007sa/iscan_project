// ~/iscan_project/src/lib/api.ts
export async function getDevices() {
  const res = await fetch("/api/devices");
  return res.json();
}

export async function discoverDevices(network?: string) {
  const res = await fetch("/api/devices/discover", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ network }),
  });
  return res.json();
}

export async function startScan(ip:string) {
  const res = await fetch("/api/scan/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  return res.json();
}
