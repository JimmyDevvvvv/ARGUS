const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

export async function fetchTopology() {
  const res = await fetch(`${API_BASE}/api/topology`)
  if (!res.ok) throw new Error(`topology fetch failed: ${res.status}`)
  return res.json()
}

export async function fetchAttackPaths() {
  const res = await fetch(`${API_BASE}/api/attack-paths`)
  if (!res.ok) throw new Error(`attack-paths fetch failed: ${res.status}`)
  return res.json()
}
