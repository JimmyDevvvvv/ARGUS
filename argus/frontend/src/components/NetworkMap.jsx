import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'

const STATUS_LABEL = {
  normal: 'NORMAL',
  vulnerable: 'VULNERABLE',
  anomaly: 'ANOMALY DETECTED',
  crownjewel: 'CROWN JEWEL',
}
const STATUS_VAR = {
  normal: '--phosphor',
  vulnerable: '--threat',
  anomaly: '--unknown',
  crownjewel: '--priority',
}

const QUERIES = [
  'show internet-facing hosts running RDP',
  'shortest path to DC-01',
  'list assets owned by Finance',
  'hosts with no EDR coverage',
]

function bracketPath(x, y, w, h, s) {
  return (
    `M${x},${y + s} L${x},${y} L${x + s},${y} ` +
    `M${x + w - s},${y} L${x + w},${y} L${x + w},${y + s} ` +
    `M${x + w},${y + h - s} L${x + w},${y + h} L${x + w - s},${y + h} ` +
    `M${x + s},${y + h} L${x},${y + h} L${x},${y + h - s}`
  )
}

function lerp01(v, a, b) {
  return Math.max(0, Math.min(1, (v - a) / (b - a)))
}

export default function NetworkMap({ sectors, attackPaths, dataSource }) {
  const svgRef = useRef(null)
  const mmRef = useRef(null)
  const zoomRef = useRef(null)
  const viewActions = useRef({})

  const [breadcrumb, setBreadcrumb] = useState('OVERVIEW')
  const [detail, setDetail] = useState(null)
  const [uptime, setUptime] = useState('00:00')
  const [queryIndex, setQueryIndex] = useState(0)

  // ambient: uptime counter
  useEffect(() => {
    let seconds = 0
    const id = setInterval(() => {
      seconds += 1
      const m = String(Math.floor(seconds / 60)).padStart(2, '0')
      const s = String(seconds % 60).padStart(2, '0')
      setUptime(`${m}:${s}`)
    }, 1000)
    return () => clearInterval(id)
  }, [])

  // ambient: cycling search placeholder
  useEffect(() => {
    const id = setInterval(() => setQueryIndex((i) => i + 1), 3500)
    return () => clearInterval(id)
  }, [])

  // Escape closes the detail panel
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') setDetail(null)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  // main D3 setup - runs once per data load
  useEffect(() => {
    if (!sectors || sectors.length === 0) return

    const svgEl = svgRef.current
    const svg = d3.select(svgEl)
    svg.selectAll('*').remove()

    const world = svg.append('g').attr('class', 'world')

    // World bounds = bounding box of all sectors, with padding.
    // For the M0 seed data this works out to exactly (0,0,1600,1120),
    // matching the original prototype - but it generalizes once M3
    // lays sectors out dynamically.
    const PAD = 60
    const minX = Math.min(...sectors.map((s) => s.x)) - PAD
    const minY = Math.min(...sectors.map((s) => s.y)) - PAD
    const maxX = Math.max(...sectors.map((s) => s.x + s.w)) + PAD
    const maxY = Math.max(...sectors.map((s) => s.y + s.h)) + PAD
    const WORLD = { x: minX, y: minY, w: maxX - minX, h: maxY - minY }

    // host lookup, for resolving attack-path hops to coordinates
    const hostsById = {}
    sectors.forEach((sec) =>
      (sec.hosts || []).forEach((h) => {
        hostsById[h.id] = { ...h, sector: sec }
      })
    )

    // ---- grid ----
    const grid = world.append('g').attr('class', 'grid')
    const GRID_STEP = 80
    for (let gx = Math.floor(WORLD.x / GRID_STEP) * GRID_STEP; gx <= WORLD.x + WORLD.w; gx += GRID_STEP) {
      grid.append('line')
        .attr('x1', gx).attr('y1', WORLD.y).attr('x2', gx).attr('y2', WORLD.y + WORLD.h)
        .attr('stroke', 'var(--grid)').attr('stroke-width', 1)
    }
    for (let gy = Math.floor(WORLD.y / GRID_STEP) * GRID_STEP; gy <= WORLD.y + WORLD.h; gy += GRID_STEP) {
      grid.append('line')
        .attr('x1', WORLD.x).attr('y1', gy).attr('x2', WORLD.x + WORLD.w).attr('y2', gy)
        .attr('stroke', 'var(--grid)').attr('stroke-width', 1)
    }

    // ---- sectors ----
    const sectorG = world.selectAll('.sector').data(sectors).join('g')
      .attr('class', 'sector')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation()
        zoomToSector(d)
      })

    sectorG.append('rect')
      .attr('x', (d) => d.x).attr('y', (d) => d.y)
      .attr('width', (d) => d.w).attr('height', (d) => d.h)
      .attr('fill', 'none').attr('stroke', 'var(--phosphor-dim)')
      .attr('stroke-width', 0.75).attr('stroke-dasharray', '2 5')

    sectorG.append('path')
      .attr('d', (d) => bracketPath(d.x, d.y, d.w, d.h, 28))
      .attr('fill', 'none').attr('stroke', 'var(--phosphor)').attr('stroke-width', 1.5)

    const sectorSummary = sectorG.append('g').attr('class', 'sector-summary')
    sectorSummary.append('text')
      .attr('x', (d) => d.x + d.w / 2).attr('y', (d) => d.y + d.h / 2 - 8)
      .attr('text-anchor', 'middle').attr('fill', 'var(--phosphor)')
      .style('font-family', 'var(--display)').style('font-weight', 600)
      .style('font-size', '30px').style('letter-spacing', '5px')
      .text((d) => d.name)
    sectorSummary.append('text')
      .attr('x', (d) => d.x + d.w / 2).attr('y', (d) => d.y + d.h / 2 + 22)
      .attr('text-anchor', 'middle').attr('fill', 'var(--text-dim)')
      .style('font-size', '14px').style('letter-spacing', '2px')
      .text((d) => `${d.cidr}  //  ${(d.hosts || []).length} CONTACTS`)

    const sectorDetail = sectorG.append('g').attr('class', 'sector-detail-label').style('opacity', 0)
    sectorDetail.append('text')
      .attr('x', (d) => d.x + 38).attr('y', (d) => d.y + 36)
      .attr('fill', 'var(--phosphor)')
      .style('font-family', 'var(--display)').style('font-weight', 600)
      .style('font-size', '17px').style('letter-spacing', '3px')
      .text((d) => d.name)
    sectorDetail.append('text')
      .attr('x', (d) => d.x + 38).attr('y', (d) => d.y + 55)
      .attr('fill', 'var(--text-dim)')
      .style('font-size', '11px').style('letter-spacing', '1px')
      .text((d) => d.cidr)

    // ---- attack paths ----
    ;(attackPaths || []).forEach((path) => {
      const points = path.hosts
        .map((id) => hostsById[id])
        .filter(Boolean)
        .map((h) => [h.x, h.y])
      if (points.length < 2) return
      world.append('path')
        .attr('class', 'attack-path')
        .attr('d', 'M' + points.map((p) => p.join(',')).join(' L'))
        .attr('fill', 'none').attr('stroke', 'var(--threat)').attr('stroke-width', 2.5)
        .attr('stroke-dasharray', '10 8')
        .style('animation', 'dash 1s linear infinite')
    })

    // ---- hosts ----
    const allHosts = sectors.flatMap((s) => (s.hosts || []).map((h) => ({ ...h, sector: s })))

    const hostG = world.selectAll('.host-group').data(allHosts).join('g')
      .attr('class', 'host-group')
      .attr('transform', (d) => `translate(${d.x},${d.y})`)
      .style('opacity', 0)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation()
        setDetail(d)
      })

    hostG.each(function (d) {
      const g = d3.select(this)
      const color = `var(${STATUS_VAR[d.status] || '--phosphor'})`
      if (d.status === 'crownjewel') {
        const rot = g.append('g').attr('transform', 'rotate(45)')
        rot.append('rect').attr('class', 'pulse')
          .attr('x', -17).attr('y', -17).attr('width', 34).attr('height', 34)
          .attr('fill', 'none').attr('stroke', color).attr('stroke-width', 1.5)
        rot.append('rect')
          .attr('x', -10).attr('y', -10).attr('width', 20).attr('height', 20)
          .attr('fill', color).attr('fill-opacity', 0.18)
          .attr('stroke', color).attr('stroke-width', 1.5)
      } else {
        if (d.status !== 'normal') {
          g.append('circle').attr('class', 'pulse').attr('r', 17)
            .attr('fill', 'none').attr('stroke', color).attr('stroke-width', 1.5)
        }
        g.append('circle').attr('r', 10)
          .attr('fill', color).attr('fill-opacity', 0.18)
          .attr('stroke', color).attr('stroke-width', 1.5)
      }
      g.append('text').attr('y', 28).attr('text-anchor', 'middle')
        .attr('fill', 'var(--text)').style('font-size', '12px').style('letter-spacing', '1px')
        .text(d.id)
      g.append('text').attr('y', 43).attr('text-anchor', 'middle')
        .attr('fill', 'var(--text-dim)').style('font-size', '10px')
        .text(d.ip)
    })

    // ---- zoom / semantic LOD ----
    const zoom = d3.zoom().scaleExtent([0.4, 5]).on('zoom', (event) => {
      world.attr('transform', event.transform)
      updateLOD(event.transform.k)
      updateMinimapViewport(event.transform)
    })
    zoomRef.current = zoom
    svg.call(zoom)

    function updateLOD(k) {
      const hostOp = lerp01(k, 1.3, 2.1)
      hostG.style('opacity', hostOp).style('pointer-events', hostOp > 0.4 ? 'auto' : 'none')
      sectorSummary.style('opacity', 1 - lerp01(k, 1.5, 2.3))
      sectorDetail.style('opacity', hostOp)
    }

    function fitView() {
      const vw = svgEl.clientWidth, vh = svgEl.clientHeight
      const s = Math.min(vw / WORLD.w, vh / WORLD.h) * 0.92
      const tx = (vw - WORLD.w * s) / 2 - WORLD.x * s
      const ty = (vh - WORLD.h * s) / 2 - WORLD.y * s
      svg.call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(s))
    }

    function zoomToSector(d) {
      const vw = svgEl.clientWidth, vh = svgEl.clientHeight
      const k = 2.4
      const cx = d.x + d.w / 2, cy = d.y + d.h / 2
      const t = d3.zoomIdentity.translate(vw / 2, vh / 2).scale(k).translate(-cx, -cy)
      svg.transition().duration(700).call(zoom.transform, t)
      setBreadcrumb(`${d.name} // ${d.cidr}`)
    }

    viewActions.current.fitView = fitView

    // background click closes detail panel
    svg.on('click', (event) => {
      if (event.target === svgEl || event.target.closest('.grid')) {
        setDetail(null)
      }
    })

    // ---- minimap ----
    const mmSvg = d3.select(mmRef.current)
    mmSvg.selectAll('*').remove()
    const mmPadFrac = 0.02
    const mmScale = (170 * (1 - 2 * mmPadFrac)) / WORLD.w
    const mmOx = 170 * mmPadFrac
    const mmOy = 119 * mmPadFrac

    mmSvg.selectAll('rect.mm-sector').data(sectors).join('rect')
      .attr('class', 'mm-sector')
      .attr('x', (d) => mmOx + (d.x - WORLD.x) * mmScale)
      .attr('y', (d) => mmOy + (d.y - WORLD.y) * mmScale)
      .attr('width', (d) => d.w * mmScale)
      .attr('height', (d) => d.h * mmScale)
      .attr('fill', 'rgba(168,224,99,.05)').attr('stroke', 'var(--phosphor-dim)').attr('stroke-width', 1)

    const mmViewport = mmSvg.append('rect')
      .attr('fill', 'var(--phosphor)').attr('fill-opacity', 0.12)
      .attr('stroke', 'var(--phosphor)').attr('stroke-width', 1)

    function updateMinimapViewport(t) {
      const vw = svgEl.clientWidth, vh = svgEl.clientHeight
      const x0 = -t.x / t.k, y0 = -t.y / t.k, w0 = vw / t.k, h0 = vh / t.k
      mmViewport
        .attr('x', mmOx + (x0 - WORLD.x) * mmScale)
        .attr('y', mmOy + (y0 - WORLD.y) * mmScale)
        .attr('width', w0 * mmScale)
        .attr('height', h0 * mmScale)
    }

    mmSvg.on('click', (event) => {
      const [mx, my] = d3.pointer(event, mmSvg.node())
      const scaleX = mmSvg.node().clientWidth / 170
      const wx = WORLD.x + (mx / scaleX - mmOx) / mmScale
      const wy = WORLD.y + (my / scaleX - mmOy) / mmScale
      const vw = svgEl.clientWidth, vh = svgEl.clientHeight
      const cur = d3.zoomTransform(svgEl)
      const t = d3.zoomIdentity.translate(vw / 2, vh / 2).scale(cur.k).translate(-wx, -wy)
      svg.transition().duration(500).call(zoom.transform, t)
    })

    // ---- initial view + resize ----
    fitView()
    const onResize = () => fitView()
    window.addEventListener('resize', onResize)

    return () => {
      window.removeEventListener('resize', onResize)
      svg.on('.zoom', null)
    }
  }, [sectors, attackPaths])

  const zoomBy = (factor) => {
    const svg = d3.select(svgRef.current)
    const zoom = zoomRef.current
    if (zoom) svg.transition().duration(300).call(zoom.scaleBy, factor)
  }

  const resetView = () => {
    viewActions.current.fitView?.()
    setBreadcrumb('OVERVIEW')
    setDetail(null)
  }

  const placeholder = QUERIES[queryIndex % QUERIES.length]

  return (
    <>
      <div className="topbar">
        <div className="logo">
          ARGUS
          <small>NETWORK SCOPE // TACTICAL TOPOLOGY</small>
        </div>
        <div className="search">
          <span>&gt;</span>
          <input id="cmd" type="text" autoComplete="off" placeholder={placeholder} />
        </div>
        <div className="status">
          <span className="dot" /> SCANNING <span>{uptime}</span>
          {dataSource === 'seed_fallback' && (
            <span className="source-flag" title="Neo4j unreachable - serving seed data">
              DEMO
            </span>
          )}
        </div>
      </div>

      <svg id="map" ref={svgRef}></svg>
      <div className="radar-sweep"></div>

      <div className="hud-panel breadcrumb">
        VIEW: <b>{breadcrumb}</b>
      </div>

      <div className="hud-panel minimap">
        <div className="hud-title">SCOPE OVERVIEW</div>
        <svg ref={mmRef} viewBox="0 0 170 119"></svg>
      </div>

      <div className="hud-panel legend">
        <div className="hud-title">CONTACT KEY</div>
        <div className="legend-item">
          <span className="swatch circle" style={{ background: 'var(--phosphor)' }} />NORMAL
        </div>
        <div className="legend-item">
          <span className="swatch circle" style={{ background: 'var(--threat)' }} />VULNERABLE / ENTRY POINT
        </div>
        <div className="legend-item">
          <span className="swatch circle" style={{ background: 'var(--unknown)' }} />ANOMALY DETECTED
        </div>
        <div className="legend-item">
          <span className="swatch diamond" style={{ background: 'var(--priority)' }} />CROWN JEWEL
        </div>
        <div className="legend-item">
          <span className="swatch line" />ACTIVE ATTACK PATH
        </div>
        <div className="legend-hint">
          SCROLL TO ZOOM // DRAG TO PAN
          <br />
          CLICK A SECTOR TO ENTER IT
          <br />
          CLICK A CONTACT FOR DETAILS
        </div>
      </div>

      <div className="hud-panel controls">
        <button onClick={() => zoomBy(1.4)} aria-label="Zoom in">+</button>
        <button onClick={() => zoomBy(1 / 1.4)} aria-label="Zoom out">-</button>
        <button className="rst" onClick={resetView} aria-label="Reset view">RST</button>
      </div>

      <div className={`hud-panel detail-panel ${detail ? 'open' : ''}`}>
        <button className="dp-close" onClick={() => setDetail(null)} aria-label="Close">
          x
        </button>
        {detail && <HostDetail host={detail} />}
      </div>
    </>
  )
}

function HostDetail({ host }) {
  const colorVar = `var(${STATUS_VAR[host.status] || '--phosphor'})`
  return (
    <div>
      <div className="dp-host">{host.id}</div>
      <div className="dp-ip">{host.ip}</div>
      <div className="dp-badge" style={{ color: colorVar }}>
        {STATUS_LABEL[host.status] || host.status}
      </div>
      <div className="dp-row"><span>SECTOR</span><span>{host.sector?.name}</span></div>
      <div className="dp-row"><span>SUBNET</span><span>{host.sector?.cidr}</span></div>
      <div className="dp-row"><span>OWNER</span><span>{host.owner}</span></div>
      <div className="dp-row"><span>OS</span><span>{host.os}</span></div>
      <div className="dp-note" style={{ color: colorVar }}>{host.note}</div>
    </div>
  )
}
