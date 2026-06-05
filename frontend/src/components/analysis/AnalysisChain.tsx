import { CheckCircle2, Circle, Loader2, XCircle } from 'lucide-react'
import type { ChainStep } from '@/api/analysis'

interface Props {
  steps: ChainStep[]
}

export default function AnalysisChain({ steps }: Props) {
  if (!steps.length) return null

  return (
    <div className="w-full">
      <div className="flex items-start gap-0 overflow-x-auto pb-1">
        {steps.map((step, i) => (
          <div key={step.id} className="flex items-start min-w-0 flex-1">
            {/* Step node */}
            <div className="flex flex-col items-center min-w-[80px]">
              <StepIcon status={step.status} />
              <div className="mt-1.5 text-center px-1">
                <div className={`text-[10px] font-medium leading-tight ${labelColor(step.status)}`}>
                  {step.label}
                </div>
                {step.detail && (
                  <div className="text-[9px] text-gray-500 mt-0.5 leading-tight truncate max-w-[76px]">
                    {step.detail}
                  </div>
                )}
              </div>
            </div>
            {/* Connector line (not after last) */}
            {i < steps.length - 1 && (
              <div className={`flex-1 h-0.5 mt-3 mx-1 rounded ${connectorColor(step.status, steps[i + 1].status)}`} />
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function StepIcon({ status }: { status: ChainStep['status'] }) {
  switch (status) {
    case 'done':
      return <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0" />
    case 'running':
      return <Loader2 className="h-6 w-6 text-blue-400 shrink-0 animate-spin" />
    case 'failed':
      return <XCircle className="h-6 w-6 text-red-400 shrink-0" />
    default:
      return <Circle className="h-6 w-6 text-gray-600 shrink-0" />
  }
}

function labelColor(status: ChainStep['status']) {
  switch (status) {
    case 'done':    return 'text-emerald-400'
    case 'running': return 'text-blue-300'
    case 'failed':  return 'text-red-400'
    default:        return 'text-gray-500'
  }
}

function connectorColor(left: ChainStep['status'], right: ChainStep['status']) {
  if (left === 'done' && (right === 'done' || right === 'running')) return 'bg-emerald-500/60'
  if (left === 'failed') return 'bg-red-500/40'
  return 'bg-gray-700'
}
