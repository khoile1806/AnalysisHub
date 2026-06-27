import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Share2, Globe, Mail, Server, Hash, FileQuestion, Activity, CheckCircle2, XCircle, Clock, PlayCircle } from 'lucide-react'
import { osintApi, type OsintGraphNode } from '@/api/osint'
import { ReactFlow, Controls, Background, MiniMap, Handle, Position, useNodesState, useEdgesState, BackgroundVariant, type Node, type Edge } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useEffect } from 'react'

// 1. Define Custom Node Component
function OsintEntityNode({ data }: { data: { node: OsintGraphNode } }) {
  const { node } = data
  
  // Choose Icon based on type
  let Icon = FileQuestion
  const t = node.type.toLowerCase()
  if (t.includes('domain')) Icon = Globe
  else if (t.includes('email')) Icon = Mail
  else if (t.includes('ip')) Icon = Server
  else if (t.includes('hash')) Icon = Hash
  else if (t.includes('cve') || t.includes('vuln')) Icon = Activity

  // Status Styling
  const styles: any = {
    done: {
      wrapper: 'border-emerald-500/40 bg-emerald-950/20 shadow-[0_0_15px_rgba(16,185,129,0.1)] hover:shadow-[0_0_20px_rgba(16,185,129,0.2)]',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      StatusIcon: CheckCircle2,
      statusColor: 'text-emerald-500'
    },
    running: {
      wrapper: 'border-blue-500/60 bg-blue-950/20 shadow-[0_0_15px_rgba(59,130,246,0.2)] hover:shadow-[0_0_20px_rgba(59,130,246,0.3)] animate-pulse-slow',
      iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      StatusIcon: PlayCircle,
      statusColor: 'text-blue-500'
    },
    pending: {
      wrapper: 'border-gray-700 bg-gray-900/50',
      iconBg: 'bg-gray-800 text-gray-400 border-gray-700',
      StatusIcon: Clock,
      statusColor: 'text-gray-500'
    },
    failed: {
      wrapper: 'border-red-500/40 bg-red-950/20',
      iconBg: 'bg-red-500/10 text-red-400 border-red-500/20',
      StatusIcon: XCircle,
      statusColor: 'text-red-500'
    },
    stopped: {
      wrapper: 'border-yellow-500/40 bg-yellow-950/20',
      iconBg: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
      StatusIcon: XCircle,
      statusColor: 'text-yellow-500'
    },
  }
  
  const style = styles[node.status] || styles.pending
  const StatusIcon = style.StatusIcon

  return (
    <div className={`px-4 py-3 rounded-xl border ${style.wrapper} backdrop-blur-md flex flex-col gap-2 w-[260px] transition-all duration-300`}>
      <Handle type="target" position={Position.Left} className="!w-2 !h-4 !rounded-sm !bg-gray-500 !border-gray-800" />
      
      <div className="flex items-center gap-3">
        {node.avatar_url
          ? <img src={node.avatar_url} alt="" referrerPolicy="no-referrer" loading="lazy"
              className="w-10 h-10 rounded-lg object-cover border border-gray-700 shrink-0 bg-gray-900" />
          : <div className={`p-2.5 rounded-lg border ${style.iconBg} shrink-0`}>
              <Icon className="w-5 h-5" />
            </div>}
        
        <div className="flex flex-col min-w-0 flex-1">
          <span className="text-[13px] font-bold text-gray-100 truncate w-full block" title={node.target}>
            {node.target}
          </span>
          <span className="text-[10px] text-gray-400 font-mono mt-0.5 tracking-wider">
            {node.type.toUpperCase()}
          </span>
        </div>
        
        <div className="shrink-0 self-start mt-1" title={`Status: ${node.status}`}>
           <StatusIcon className={`w-4 h-4 ${style.statusColor}`} />
        </div>
      </div>
      
      <div className="flex items-center justify-between mt-1 pt-2 border-t border-gray-800/50">
        <span className="text-[10px] text-gray-500 font-medium">FINDINGS</span>
        <span className={`text-[11px] font-bold ${node.findings > 0 ? 'text-red-400' : 'text-gray-400'}`}>
          {node.findings}
        </span>
      </div>

      <Handle type="source" position={Position.Right} className="!w-2 !h-4 !rounded-sm !bg-gray-500 !border-gray-800" />
    </div>
  )
}

const nodeTypes = {
  osintNode: OsintEntityNode,
}

// 2. Main Graph Component
export default function OsintGraphView({ scanId, live }: { scanId: string; live: boolean }) {
  const navigate = useNavigate()
  
  const { data } = useQuery({
    queryKey: ['osint-graph', scanId],
    queryFn: () => osintApi.graph(scanId),
    refetchInterval: live ? 4000 : false,
  })

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  useEffect(() => {
    if (!data || data.nodes.length <= 1) return

    // Layout math (DAG Left-to-Right)
    const byDepth: Record<number, OsintGraphNode[]> = {}
    data.nodes.forEach((n) => {
      if (!byDepth[n.depth]) byDepth[n.depth] = []
      byDepth[n.depth].push(n)
    })

    const colW = 340
    const rowH = 120
    const padX = 50
    const padY = 50
    const maxRows = Math.max(...Object.values(byDepth).map((a) => a.length))

    const newNodes = data.nodes.map(n => {
      const depthN = n.depth
      const rowIdx = byDepth[n.depth].findIndex(x => x.id === n.id)
      const arrLen = byDepth[n.depth].length
      
      const x = padX + depthN * colW
      const y = padY + rowIdx * rowH + ((maxRows - arrLen) * rowH) / 2
      
      return {
        id: n.id,
        type: 'osintNode',
        position: { x, y },
        data: { node: n }
      }
    })

    const newEdges = data.edges.map(e => ({
      id: `${e.from}-${e.to}`,
      source: e.from,
      target: e.to,
      type: 'smoothstep', // Use elegant smoothstep routing
      animated: data.nodes.find(n => n.id === e.to)?.status === 'running',
      style: { stroke: '#4b5563', strokeWidth: 1.5 },
    }))

    setNodes(newNodes)
    setEdges(newEdges)
  }, [data, setNodes, setEdges])

  if (!data || data.nodes.length <= 1) return null

  return (
    <div className="card p-4 space-y-3 flex flex-col h-[600px]">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
        <Share2 className="h-4 w-4 text-emerald-400" /> Interactive Investigation Graph · {data.nodes.length} entities
      </h3>
      
      <div className="flex-1 border border-gray-800 rounded-xl overflow-hidden bg-gray-950/40 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => navigate(`/osint/${node.id}`)}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.2}
          maxZoom={3}
          className="dark"
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={2} color="#374151" />
          <Controls className="!bg-gray-900 !border-gray-800 !fill-gray-300" />
          <MiniMap 
            className="!bg-gray-900/80 !border-gray-800 !rounded-lg"
            maskColor="rgba(0,0,0,0.4)"
            nodeColor={(n: any) => n.data.node.status === 'done' ? '#10b981' : '#6b7280'}
          />
        </ReactFlow>
        
        {/* Style tweaks for React Flow injected controls */}
        <style dangerouslySetInnerHTML={{__html: `
          .react-flow__controls-button {
            background: #111827 !important;
            border-bottom: 1px solid #1f2937 !important;
            fill: #9ca3af !important;
          }
          .react-flow__controls-button:hover {
            background: #1f2937 !important;
            fill: #f3f4f6 !important;
          }
        `}} />
      </div>
    </div>
  )
}
