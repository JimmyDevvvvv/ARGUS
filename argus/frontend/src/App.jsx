import { useEffect, useState } from 'react'
import NetworkMap from './components/NetworkMap.jsx'
import { fetchTopology, fetchAttackPaths } from './api.js'

export default function App() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([fetchTopology(), fetchAttackPaths()])
      .then(([topology, attackPaths]) => {
        setData({
          sectors: topology.sectors,
          attackPaths: attackPaths.paths,
          source: topology.source,
        })
      })
      .catch((e) => setError(e.message))
  }, [])

  if (error) {
    return (
      <div className="load-error">
        Failed to load topology: {error}
        <br />
        Is the backend running on http://localhost:8000?
      </div>
    )
  }
  if (!data) {
    return <div className="load-status">CONNECTING TO ARGUS API...</div>
  }
  return (
    <NetworkMap
      sectors={data.sectors}
      attackPaths={data.attackPaths}
      dataSource={data.source}
    />
  )
}
