import { useEffect, useLayoutEffect, useRef, useState, type FormEvent, type PointerEvent as ReactPointerEvent } from 'react'
import { AnimatePresence, MotionConfig, motion } from 'motion/react'
import {
  analyzePrivacy,
  getAuditLogs,
  runWorkflow,
  submitApproval,
  type AuditLog,
  type PrivacyEntity,
  type WorkflowResponse,
} from './api'
import { maskEntitiesLocally } from './privacy'
import {
  AgentActivityPage,
  AuthorizationPage,
  PrivacyGuardPage,
  type PrivacyComparison,
  type PrivacySnapshot,
  type WorkflowSnapshot,
} from './security-pages'
import './App.css'

const splineEmbedUrl = import.meta.env.VITE_SPLINE_EMBED_URL?.trim()

const navItems = [
  { label: 'Overview', icon: '◫' },
  { label: 'AI Assistant', icon: '✳' },
  { label: 'Privacy Guard', icon: '⬡' },
  { label: 'Agent Activity', icon: '⌁' },
  { label: 'Authorization', icon: '⛨' },
  { label: 'Audit Logs', icon: '▤' },
]

type DashboardActivity = {
  id: string
  icon: string
  title: string
  detail: string
  tag: string
  color: 'green' | 'amber' | 'red'
}

type PipelinePhase = 'idle' | 'privacy' | 'privacy-complete' | 'agent' | 'authorization' | 'complete' | 'error'

function DataFlowVisualizer({
  phase,
  privacyComplete,
  workflowComplete,
}: {
  phase: PipelinePhase
  privacyComplete: boolean
  workflowComplete: boolean
}) {
  const privacyDone = privacyComplete || ['privacy-complete', 'agent', 'authorization', 'complete'].includes(phase)
  const agentDone = workflowComplete || ['authorization', 'complete'].includes(phase)
  const authorizationDone = phase === 'complete' || (phase === 'idle' && workflowComplete)
  const errorStep = phase === 'error' ? (privacyComplete ? 'agent' : 'privacy') : null
  const statuses = [
    privacyDone ? 'complete' : phase === 'privacy' ? 'active' : errorStep === 'privacy' ? 'error' : 'waiting',
    agentDone ? 'complete' : phase === 'agent' ? 'active' : errorStep === 'agent' ? 'error' : 'waiting',
    authorizationDone ? 'complete' : phase === 'authorization' ? 'active' : 'waiting',
  ] as const
  const titles = ['Privacy Guard', 'Agent Activity', 'Authorization Gateway']
  const details = [
    privacyDone ? 'Sensitive spans masked locally' : 'Detect and mask sensitive data',
    agentDone ? 'Workflow and provenance received' : 'Process sanitized content',
    authorizationDone ? 'Backend decision received' : 'Evaluate proposed actions',
  ]
  const symbols = ['⬡', '⌁', '⛨']
  const connectorClasses = [privacyDone ? 'complete' : phase === 'privacy' ? 'active' : '', agentDone ? 'complete' : phase === 'agent' || phase === 'authorization' ? 'active' : '']

  return (
    <section className="data-flow-panel" aria-label="Secure task data flow">
      <div className="data-flow-heading">
        <div>
          <span className="eyebrow">SECURE DATA FLOW</span>
          <h2>Every step stays visible.</h2>
        </div>
        <span className={`flow-state ${phase === 'error' ? 'error' : ''}`} role="status">
          {phase === 'privacy' ? 'SCANNING' : phase === 'agent' ? 'AGENT RUNNING' : phase === 'authorization' ? 'CHECKING POLICY' : phase === 'error' ? 'NEEDS ATTENTION' : phase === 'complete' ? 'COMPLETE' : privacyDone ? 'READY FOR AGENT' : 'AWAITING REQUEST'}
        </span>
      </div>
      <div className="data-flow-track">
        {titles.map((title, index) => (
          <div className={`flow-step ${statuses[index]}`} key={title}>
            <span className="flow-step-icon" aria-hidden="true">{symbols[index]}</span>
            <span className="flow-step-copy">
              <strong>{title}</strong>
              <small>{details[index]}</small>
            </span>
            <span className="flow-step-indicator" aria-hidden="true">
              {statuses[index] === 'complete' ? '✓' : statuses[index] === 'active' ? '…' : statuses[index] === 'error' ? '!' : String(index + 1).padStart(2, '0')}
            </span>
            {index < 2 && (
              <span className={`flow-connector ${connectorClasses[index]}`} aria-hidden="true">
                <i />
              </span>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}

function AssistantForm({
  onPrivacyComplete,
  onWorkflowComplete,
  onApprovalSubmitted,
}: {
  onPrivacyComplete: (snapshot: PrivacySnapshot, comparison: PrivacyComparison) => void
  onWorkflowComplete: (snapshot: WorkflowSnapshot) => void
  onApprovalSubmitted: (actionId: string, decision: 'approve' | 'reject') => void
}) {
  const [task, setTask] = useState('')
  const [sourceType, setSourceType] = useState<'email' | 'document'>('email')
  const [sourceId, setSourceId] = useState('')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [workflowLoading, setWorkflowLoading] = useState(false)
  const [flowPhase, setFlowPhase] = useState<PipelinePhase>('idle')
  const [error, setError] = useState('')
  const [workflowError, setWorkflowError] = useState('')
  const [entities, setEntities] = useState<PrivacyEntity[]>([])
  const [maskedText, setMaskedText] = useState('')
  const [placeholderToOriginal, setPlaceholderToOriginal] =
    useState<Record<string, string>>({})
  const [hasAnalyzed, setHasAnalyzed] = useState(false)
  const [taskId, setTaskId] = useState('')
  const [workflowResult, setWorkflowResult] =
    useState<WorkflowResponse | null>(null)
  const [approvalLoadingId, setApprovalLoadingId] = useState<string | null>(
    null,
  )
  const [approvalMessages, setApprovalMessages] = useState<
    Record<string, string>
  >({})
  const [approvalErrors, setApprovalErrors] = useState<Record<string, string>>(
    {},
  )

  async function handlePrivacyCheck(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setWorkflowError('')
    setWorkflowResult(null)
    setHasAnalyzed(false)

    if (!task.trim() || !sourceId.trim() || !content.trim()) {
      setError('Please complete the task, source ID, and content fields.')
      return
    }

    setFlowPhase('privacy')
    setLoading(true)
    const newTaskId = `TASK_${Date.now()}`

    try {
      const result = await analyzePrivacy(`REQ_${Date.now()}`, content)

      if (result.status !== 'success') {
        throw new Error('The privacy check did not complete successfully.')
      }

      const masking = maskEntitiesLocally(content, result.entities)

      setTaskId(newTaskId)
      setEntities(result.entities)
      setMaskedText(masking.maskedText)
      setPlaceholderToOriginal(masking.placeholderToOriginal)
      const entityCounts = result.entities.reduce<Record<string, number>>(
        (counts, entity) => {
          counts[entity.type] = (counts[entity.type] ?? 0) + 1
          return counts
        },
        {},
      )
      onPrivacyComplete({
        total: result.entities.length,
        entityCounts,
        sourceId,
        sourceType,
        checkedAt: new Date().toISOString(),
      }, {
        originalText: content,
        maskedText: masking.maskedText,
        entities: result.entities,
      })
      setHasAnalyzed(true)
      setFlowPhase('privacy-complete')
    } catch (requestError) {
      setFlowPhase('error')
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not connect to the privacy service.',
      )
    } finally {
      setLoading(false)
    }
  }

  async function handleRunWorkflow() {
    setWorkflowError('')
    setWorkflowLoading(true)
    setFlowPhase('agent')

    try {
      const result = await runWorkflow({
        task_id: taskId,
        user_task: task,
        sanitized_content: maskedText,
        source: {
          source_id: sourceId,
          source_type: sourceType,
        },
      })

      setWorkflowResult(result)
      onWorkflowComplete({ result, taskId, sourceId, sourceType })
      setFlowPhase('authorization')
      await new Promise((resolve) => window.setTimeout(resolve, 500))
      setFlowPhase('complete')
    } catch (requestError) {
      setFlowPhase('error')
      setWorkflowError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not connect to the workflow service.',
      )
    } finally {
      setWorkflowLoading(false)
    }
  }

  async function handleApproval(
    actionId: string,
    decision: 'approve' | 'reject',
  ) {
    setApprovalLoadingId(actionId)
    setApprovalErrors((current) => ({ ...current, [actionId]: '' }))
    setApprovalMessages((current) => ({ ...current, [actionId]: '' }))

    try {
      await submitApproval(actionId, decision)
      onApprovalSubmitted(actionId, decision)
      setApprovalMessages((current) => ({
        ...current,
        [actionId]: `Your ${decision} decision was submitted.`,
      }))
    } catch (approvalError) {
      setApprovalErrors((current) => ({
        ...current,
        [actionId]:
          approvalError instanceof Error
            ? approvalError.message
            : 'Could not submit the approval decision.',
      }))
    } finally {
      setApprovalLoadingId(null)
    }
  }

  return (
    <section className="assistant-screen">
      <div className="eyebrow">SECURE WORKFLOW</div>
      <h1>Submit a task</h1>
      <p className="subtitle">
        Add your request and simulated email or document content.
      </p>

      <DataFlowVisualizer
        phase={flowPhase}
        privacyComplete={hasAnalyzed}
        workflowComplete={Boolean(workflowResult)}
      />

      <form className="assistant-card" onSubmit={handlePrivacyCheck}>
        <label htmlFor="user-task">What should the AI assistant do?</label>
        <input
          id="user-task"
          value={task}
          onChange={(event) => setTask(event.target.value)}
          placeholder="Summarize my payroll email"
        />

        <div className="assistant-fields">
          <div>
            <label htmlFor="source-type">Content type</label>
            <select
              id="source-type"
              value={sourceType}
              onChange={(event) =>
                setSourceType(event.target.value as 'email' | 'document')
              }
            >
              <option value="email">Simulated email</option>
              <option value="document">Simulated document / PDF text</option>
            </select>
          </div>

          <div>
            <label htmlFor="source-id">Source ID</label>
            <input
              id="source-id"
              value={sourceId}
              onChange={(event) => setSourceId(event.target.value)}
              placeholder="e.g. EMAIL_001"
            />
          </div>
        </div>

        <label htmlFor="source-content">Email or document text</label>
        <textarea
          id="source-content"
          rows={8}
          value={content}
          onChange={(event) => setContent(event.target.value)}
          placeholder="Paste test email or document text here. Avoid real personal data."
        />

        <button className="primary-button" type="submit" disabled={loading}>
          {loading ? 'Checking privacy…' : 'Analyze and mask'}
        </button>

        {loading && (
          <motion.div
            className="scan-status"
            role="status"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <span className="scan-spinner" aria-hidden="true" />
            <span>
              <strong>Privacy scan in progress</strong>
              <small>Checking sensitive spans before the agent workflow.</small>
            </span>
          </motion.div>
        )}

        {error && <p className="assistant-error">{error}</p>}

        {hasAnalyzed && (
          <motion.section
            className="privacy-results"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          >
            <h2>Privacy check complete</h2>

            {entities.length > 0 ? (
              <>
                <p>
                  Detected {entities.length} sensitive item
                  {entities.length === 1 ? '' : 's'}:
                </p>
                <ul>
                  {entities.map((entity) => (
                    <li key={`${entity.start}-${entity.end}-${entity.type}`}>
                      {entity.type} · {(entity.confidence * 100).toFixed(0)}%
                      confidence
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p>No sensitive items were detected.</p>
            )}

            <h3>Masked preview</h3>
            <pre>{maskedText}</pre>
            <p className="mapping-note">
              Original values are held in this screen’s memory only (
              {Object.keys(placeholderToOriginal).length} masked).
            </p>

            <button
              className="primary-button"
              type="button"
              onClick={handleRunWorkflow}
              disabled={workflowLoading}
            >
              {workflowLoading ? 'Running workflow…' : 'Continue to agent'}
            </button>

            {workflowError && (
              <p className="assistant-error">{workflowError}</p>
            )}

            {workflowResult && (
              <div className="workflow-results">
                <h2>Agent result</h2>
                <p>{workflowResult.assistant_response}</p>

                {workflowResult.actions.map((action) => (
                  <article className="workflow-action" key={action.action_id}>
                    <strong
                      className={`decision ${action.decision.toLowerCase()}`}
                    >
                      {action.decision}
                    </strong>
                    <span>Action: {action.action_id}</span>
                    <p>{action.reason}</p>

                    {action.decision === 'APPROVE' && (
                      <div className="approval-controls">
                        <button
                          type="button"
                          disabled={approvalLoadingId === action.action_id}
                          onClick={() =>
                            handleApproval(action.action_id, 'approve')
                          }
                        >
                          {approvalLoadingId === action.action_id
                            ? 'Submitting…'
                            : 'Approve'}
                        </button>
                        <button
                          type="button"
                          disabled={approvalLoadingId === action.action_id}
                          onClick={() =>
                            handleApproval(action.action_id, 'reject')
                          }
                        >
                          Reject
                        </button>
                      </div>
                    )}

                    {approvalMessages[action.action_id] && (
                      <p className="mapping-note">
                        {approvalMessages[action.action_id]}
                      </p>
                    )}

                    {approvalErrors[action.action_id] && (
                      <p className="assistant-error">
                        {approvalErrors[action.action_id]}
                      </p>
                    )}
                  </article>
                ))}
              </div>
            )}
          </motion.section>
        )}
      </form>
    </section>
  )
}

function AuditLogs() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    let isCurrent = true

    getAuditLogs()
      .then((response) => {
        if (isCurrent) setLogs(response.logs)
      })
      .catch((requestError: unknown) => {
        if (isCurrent) {
          setError(
            requestError instanceof Error
              ? requestError.message
              : 'Could not load audit history.',
          )
        }
      })
      .finally(() => {
        if (isCurrent) setLoading(false)
      })

    return () => {
      isCurrent = false
    }
  }, [reloadToken])

  function refreshLogs() {
    setLoading(true)
    setError('')
    setReloadToken((value) => value + 1)
  }

  return (
    <section className="audit-screen">
      <div className="audit-heading">
        <div>
          <div className="eyebrow">SECURITY HISTORY</div>
          <h1>Audit Logs</h1>
          <p className="subtitle">
            Review recorded decisions and their reasons.
          </p>
        </div>
        <button
          className="audit-refresh"
          type="button"
          onClick={refreshLogs}
          disabled={loading}
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="audit-message error" role="alert">
          <span>{error}</span>
          <button
            type="button"
            onClick={refreshLogs}
          >
            Try again
          </button>
        </div>
      )}
      {loading && <p className="audit-message">Loading audit records…</p>}
      {!loading && !error && logs.length === 0 && (
        <p className="audit-message">No audit records are available yet.</p>
      )}

      {!loading && !error && logs.length > 0 && (
        <div className="audit-table-wrap">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Action ID</th>
                <th>Decision</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const timestamp = new Date(log.timestamp)
                const displayTime = Number.isNaN(timestamp.getTime())
                  ? log.timestamp
                  : timestamp.toLocaleString()

                return (
                  <tr key={`${log.action_id}-${log.timestamp}`}>
                    <td>{displayTime}</td>
                    <td>{log.action_id}</td>
                    <td>
                      <span
                        className={`audit-decision ${log.decision.toLowerCase()}`}
                      >
                        {log.decision}
                      </span>
                    </td>
                    <td>{log.reason}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function Metric({
  title,
  value,
  trend,
  icon,
  color,
  history,
}: {
  title: string
  value: string
  trend: string
  icon: string
  color: string
  history: number[]
}) {
  const maxCount = Math.max(...history, 1)

  return (
    <article className="metric-card">
      <div className="metric-head">
        <span>{title}</span>
        <span className={`metric-icon ${color}`}>{icon}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-foot">
        <span>{trend}</span>
      </div>
      <div
        className={`sparkline ${color}`}
        role="img"
        aria-label={`${title} counts over recent updates: ${history.join(', ')}`}
      >
        {history.map((count, index) => (
          <i
            key={`${index}-${count}`}
            style={{ height: `${Math.max(3, Math.round((count / maxCount) * 28))}px` }}
          />
        ))}
      </div>
    </article>
  )
}

function SessionTrendChart({ history }: { history: number[][] }) {
  const chartSeries = [
    { label: 'Requests protected', values: history[0] ?? [0], color: '#ad96ff' },
    { label: 'Sensitive items masked', values: history[1] ?? [0], color: '#70dcb6' },
    { label: 'Actions blocked', values: history[2] ?? [0], color: '#ff9991' },
    { label: 'Awaiting approval', values: history[3] ?? [0], color: '#f4c66d' },
  ]
  const maxCount = Math.max(1, ...chartSeries.flatMap((series) => series.values))
  const hasActivity = chartSeries.some((series) => series.values.some((count) => count > 0))
  const chartWidth = 680
  const chartHeight = 190
  const left = 34
  const right = 668
  const top = 18
  const bottom = 156
  const coordinates = (values: number[]) => values.map((count, index) => {
    const x = values.length === 1
      ? right
      : left + ((right - left) * index) / (values.length - 1)
    const y = bottom - (count / maxCount) * (bottom - top)
    return `${x},${y}`
  }).join(' ')

  return (
    <section className="panel trend-panel" data-scroll-reveal aria-labelledby="session-trend-title">
      <div className="panel-heading">
        <div>
          <h3 id="session-trend-title">Session trend</h3>
          <p>Live counts across recent updates in this session.</p>
        </div>
        {hasActivity && <span className="trend-live"><i /> LIVE SESSION</span>}
      </div>

      {hasActivity ? (
        <>
          <svg
            className="session-chart"
            viewBox={`0 0 ${chartWidth} ${chartHeight}`}
            role="img"
            aria-label={chartSeries.map((series) => `${series.label}: ${series.values.join(', ')}`).join('. ')}
          >
            <text className="chart-axis-label" x="4" y={top + 4}>{maxCount}</text>
            <text className="chart-axis-label" x="18" y={bottom + 4}>0</text>
            {[top, (top + bottom) / 2, bottom].map((y) => (
              <line key={y} className="chart-gridline" x1={left} x2={right} y1={y} y2={y} />
            ))}
            {chartSeries.map((series) => (
              <g key={series.label}>
                {series.values.length > 1 && (
                  <polyline
                    points={coordinates(series.values)}
                    fill="none"
                    stroke={series.color}
                    strokeWidth="2.5"
                    strokeLinejoin="round"
                    strokeLinecap="round"
                    vectorEffect="non-scaling-stroke"
                  />
                )}
                <circle
                  cx={series.values.length === 1 ? right : right}
                  cy={bottom - ((series.values.at(-1) ?? 0) / maxCount) * (bottom - top)}
                  r="4"
                  fill={series.color}
                  className="chart-current-point"
                />
              </g>
            ))}
          </svg>
          <div className="chart-legend">
            {chartSeries.map((series) => (
              <span key={series.label}>
                <i style={{ backgroundColor: series.color }} />{series.label}
              </span>
            ))}
          </div>
        </>
      ) : (
        <p className="chart-empty">Complete a secure request to build your session graph.</p>
      )}
    </section>
  )
}

function Dashboard({
  onNavigate,
  playIntro,
  onIntroComplete,
  stats,
  recentActivity,
  privacySnapshot,
  workflowSnapshot,
  metricHistory,
}: {
  onNavigate: (page: string) => void
  playIntro: boolean
  onIntroComplete: () => void
  stats: {
    protectedRequests: number
    maskedItems: number
    blockedActions: number
    pendingApprovals: number
  }
  recentActivity: DashboardActivity[]
  privacySnapshot: PrivacySnapshot | null
  workflowSnapshot: WorkflowSnapshot | null
  metricHistory: number[][]
}) {
  const orbRef = useRef<HTMLDivElement>(null)
  const orbVisualRef = useRef<HTMLDivElement>(null)
  const workflowActions = workflowSnapshot?.result.actions ?? []
  const postureLabel = stats.pendingApprovals > 0
    ? 'REVIEW NEEDED'
    : workflowSnapshot
      ? workflowActions.some((action) => action.decision === 'BLOCK')
        ? 'POLICY ENFORCED'
        : 'WORKFLOW CHECKED'
      : privacySnapshot
        ? 'PRIVACY CHECKED'
        : 'AWAITING REQUEST'
  useLayoutEffect(() => {
    const slot = orbRef.current
    const orb = orbVisualRef.current
    if (!slot || !orb) return

    if (!playIntro) {
      orb.style.visibility = 'visible'
      return
    }

    const bounds = slot.getBoundingClientRect()
    const centerX = bounds.left + bounds.width / 2
    const centerY = bounds.top + bounds.height / 2
    orb.style.setProperty('--intro-x', `${window.innerWidth / 2 - centerX}px`)
    orb.style.setProperty('--intro-y', `${window.innerHeight / 2 - centerY}px`)
    orb.classList.add('orb-animate')
  }, [playIntro])

  useEffect(() => {
    const revealTargets = document.querySelectorAll<HTMLElement>('[data-scroll-reveal]')
    if (!('IntersectionObserver' in window)) {
      revealTargets.forEach((target) => target.classList.add('is-revealed'))
      return
    }

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-revealed')
          observer.unobserve(entry.target)
        }
      })
    }, { threshold: 0.12, rootMargin: '0px 0px -28px 0px' })

    revealTargets.forEach((target) => observer.observe(target))
    return () => observer.disconnect()
  }, [])

  function handleHeroPointerMove(event: ReactPointerEvent<HTMLElement>) {
    if (event.pointerType === 'touch') return
    const bounds = event.currentTarget.getBoundingClientRect()
    const x = (event.clientX - bounds.left - bounds.width / 2) / bounds.width
    const y = (event.clientY - bounds.top - bounds.height / 2) / bounds.height
    const layers: Record<string, number> = {
      '--hero-glow-x': x * 56,
      '--hero-glow-y': y * 36,
      '--aura-x': x * -24,
      '--aura-y': y * -16,
      '--grid-x': x * -32,
      '--grid-y': y * -24,
      '--copy-x': x * -20,
      '--copy-y': y * -12,
      '--spline-x': x * 56,
      '--spline-y': y * 42,
      '--orb-far-x': x * 22,
      '--orb-far-y': y * 20,
      '--orbit-one-x': x * 54,
      '--orbit-one-y': y * 40,
      '--orbit-two-x': x * -72,
      '--orbit-two-y': y * -54,
      '--shield-x': x * 44,
      '--shield-y': y * 40,
      '--dot-one-x': x * 68,
      '--dot-one-y': y * 48,
      '--dot-two-x': x * -58,
      '--dot-two-y': y * -44,
      '--dot-three-x': x * 48,
      '--dot-three-y': y * -40,
    }

    Object.entries(layers).forEach(([property, value]) => {
      event.currentTarget.style.setProperty(property, `${value.toFixed(1)}px`)
    })
  }

  function resetHeroParallax(event: ReactPointerEvent<HTMLElement>) {
    const properties = [
      '--hero-glow-x', '--hero-glow-y', '--aura-x', '--aura-y', '--grid-x', '--grid-y',
      '--copy-x', '--copy-y',
      '--spline-x', '--spline-y',
      '--orb-far-x', '--orb-far-y', '--orbit-one-x', '--orbit-one-y', '--orbit-two-x',
      '--orbit-two-y', '--shield-x', '--shield-y', '--dot-one-x', '--dot-one-y',
      '--dot-two-x', '--dot-two-y', '--dot-three-x', '--dot-three-y',
    ]
    properties.forEach((property) => event.currentTarget.style.removeProperty(property))
  }

  return (
    <>
      <section className="welcome-row">
        <div>
          <div className="eyebrow">
            {new Date().toLocaleDateString(undefined, {
              weekday: 'long', month: 'long', day: 'numeric', year: 'numeric',
            }).toUpperCase()}
          </div>
          <h1>Your agents, under control.</h1>
          <p className="subtitle">
            Keep sensitive data safe and every agent action accountable.
          </p>
        </div>
        <button
          className="primary-button"
          onClick={() => onNavigate('AI Assistant')}
        >
          <span>＋</span> New secure request
        </button>
      </section>

      <section
        className="hero-panel"
        onPointerMove={handleHeroPointerMove}
        onPointerLeave={resetHeroParallax}
      >
        <div className="hero-copy">
          <div className="hero-kicker">
            <span className="sparkle">✦</span> YOUR SECURITY COMMAND CENTER
          </div>
          <h2>
            Move fast.
            <br />
            <em>Stay protected.</em>
          </h2>
          <p>
            AgentShield checks sensitive information and agent actions before
            they reach external AI tools.
          </p>
          <button
            className="hero-button"
            onClick={() => onNavigate('AI Assistant')}
          >
            Start a secure request <span>↗</span>
          </button>
        </div>
        <div ref={orbRef} className="orb-slot" aria-hidden="true">
          <div
            ref={orbVisualRef}
            className="orb-wrap"
            onAnimationEnd={playIntro ? onIntroComplete : undefined}
          >
              {splineEmbedUrl ? (
                <iframe
                  className="spline-embed"
                  src={splineEmbedUrl}
                  title="Decorative AgentShield 3D shield"
                  loading="lazy"
                  tabIndex={-1}
                />
              ) : (
                <>
                  <div className="orb-grid" />
                  <div className="orbit orbit-one" />
                  <div className="orbit orbit-two" />
                  <div className="shield-orb">
                    <span>✦</span>
                  </div>
                  <div className="orbit-dot dot-one" />
                  <div className="orbit-dot dot-two" />
                  <div className="orbit-dot dot-three" />
                </>
              )}
          </div>
        </div>
        <div className="hero-foot">
          <span>
            <i /> PRIVACY WORKFLOW
          </span>
          <span>
            LOCAL MASKING <b>·</b> POLICY CHECKS <b>·</b> AUDIT TRAIL
          </span>
        </div>
      </section>

      <section
        className="metrics-grid"
        aria-label="Security summary for this session"
      >
        <Metric
          title="Requests protected"
          value={stats.protectedRequests.toLocaleString()}
          trend="This session"
          icon="✳"
          color="violet"
          history={metricHistory[0]}
        />
        <Metric
          title="Sensitive items masked"
          value={stats.maskedItems.toLocaleString()}
          trend="Detected this session"
          icon="⬡"
          color="mint"
          history={metricHistory[1]}
        />
        <Metric
          title="Actions blocked"
          value={stats.blockedActions.toLocaleString()}
          trend="By policy this session"
          icon="⛨"
          color="coral"
          history={metricHistory[2]}
        />
        <Metric
          title="Awaiting approval"
          value={stats.pendingApprovals.toLocaleString()}
          trend="Needs your review"
          icon="◷"
          color="gold"
          history={metricHistory[3]}
        />
      </section>

      <SessionTrendChart history={metricHistory} />

      <section className="lower-grid" data-scroll-reveal>
        <article className="panel activity-panel">
          <div className="panel-heading">
            <div>
              <h3>Recent activity</h3>
              <p>Events recorded during this session.</p>
            </div>
            <button
              className="text-button"
              onClick={() => onNavigate('Agent Activity')}
            >
              View all <span>→</span>
            </button>
          </div>
          <div className="activity-list">
            {recentActivity.length > 0 ? recentActivity.map((item) => (
              <button
                className="activity-row"
                type="button"
                key={item.id}
                onClick={() => onNavigate('Agent Activity')}
                aria-label={`View agent activity: ${item.title}`}
              >
                <div className={`activity-icon ${item.color}`}>{item.icon}</div>
                <div className="activity-text">
                  <strong>{item.title}</strong>
                  <small>{item.detail}</small>
                </div>
                <span className={`status ${item.color}`}>{item.tag}</span>
                <span className="row-arrow">›</span>
              </button>
            )) : (
              <p className="empty-activity">No activity yet. Complete a privacy scan to see events here.</p>
            )}
          </div>
        </article>

        <article className="panel posture-panel">
          <div className="panel-heading">
            <div>
              <h3>Security posture</h3>
              <p>Live results from this session.</p>
            </div>
            <span className={`posture-ok ${stats.pendingApprovals > 0 ? 'review' : ''}`}>● {postureLabel}</span>
          </div>
          <div className="posture-score">
            <div className={`posture-mark ${workflowSnapshot || privacySnapshot ? 'checked' : ''}`} aria-hidden="true">
              {stats.pendingApprovals > 0 ? '!' : workflowSnapshot || privacySnapshot ? '✓' : '·'}
            </div>
            <div>
              <strong>{workflowSnapshot ? 'Workflow evaluated' : privacySnapshot ? 'Privacy scan completed' : 'No request checked yet'}</strong>
              <p>{workflowSnapshot ? `${workflowActions.length} policy decision${workflowActions.length === 1 ? '' : 's'} received.` : 'Run a secure request to see protection status.'}</p>
            </div>
          </div>
          <div className="posture-items">
            <div>
              <span className={`checkmark ${privacySnapshot ? '' : 'inactive'}`}>{privacySnapshot ? '✓' : '·'}</span> Privacy scan
              <strong>{privacySnapshot ? `${privacySnapshot.total} detected` : 'Not checked'}</strong>
            </div>
            <div>
              <span className={`checkmark ${workflowSnapshot ? '' : 'inactive'}`}>{workflowSnapshot ? '✓' : '·'}</span> Agent policy
              <strong>{workflowSnapshot ? `${workflowActions.length} decision${workflowActions.length === 1 ? '' : 's'}` : 'Not checked'}</strong>
            </div>
            <div>
              <span className={`checkmark ${stats.pendingApprovals ? 'pending' : workflowSnapshot ? '' : 'inactive'}`}>{stats.pendingApprovals ? '!' : workflowSnapshot ? '✓' : '·'}</span> Human review
              <strong>{stats.pendingApprovals ? `${stats.pendingApprovals} awaiting` : workflowSnapshot ? 'No pending review' : 'Not checked'}</strong>
            </div>
          </div>
        </article>

      </section>

      <footer className="page-footer">
        <span>
          AGENTSHIELD <b>·</b> KEEPING YOUR AI WORKFLOWS SAFE
        </span>
        <span>
          SESSION OVERVIEW
        </span>
      </footer>
    </>
  )
}

function App() {
  const [activePage, setActivePage] = useState('Overview')
  const [introActive, setIntroActive] = useState(false)
  const [brandSplashVisible, setBrandSplashVisible] = useState(true)
  const [privacySnapshot, setPrivacySnapshot] = useState<PrivacySnapshot | null>(null)
  const [privacyComparison, setPrivacyComparison] = useState<PrivacyComparison | null>(null)
  const [workflowSnapshot, setWorkflowSnapshot] = useState<WorkflowSnapshot | null>(null)
  const [dashboardStats, setDashboardStats] = useState({
    protectedRequests: 0,
    maskedItems: 0,
    blockedActions: 0,
  })
  const [recentActivity, setRecentActivity] = useState<DashboardActivity[]>([])
  const activitySequence = useRef(0)
  const recordedWorkflowTasks = useRef(new Set<string>())
  const [approvalSubmissions, setApprovalSubmissions] = useState<
    Record<string, 'approve' | 'reject'>
  >({})

  useEffect(() => {
    const splashTimer = window.setTimeout(() => {
      setBrandSplashVisible(false)
    }, 1800)

    return () => window.clearTimeout(splashTimer)
  }, [])

  function addRecentActivity(entry: Omit<DashboardActivity, 'id'>) {
    activitySequence.current += 1
    const id = `activity-${activitySequence.current}`
    setRecentActivity((current) => [{ ...entry, id }, ...current].slice(0, 5))
  }

  function handlePrivacyComplete(snapshot: PrivacySnapshot, comparison: PrivacyComparison) {
    setPrivacySnapshot(snapshot)
    setPrivacyComparison(comparison)
    setWorkflowSnapshot(null)
    setApprovalSubmissions({})
    setDashboardStats((current) => ({
      ...current,
      protectedRequests: current.protectedRequests + 1,
      maskedItems: current.maskedItems + snapshot.total,
    }))
    addRecentActivity({
      icon: '⬡',
      title: 'Privacy scan completed',
      detail: `${snapshot.total} sensitive item${snapshot.total === 1 ? '' : 's'} masked before processing`,
      tag: 'SCANNED',
      color: 'green',
    })
  }

  function handleWorkflowComplete(snapshot: WorkflowSnapshot) {
    setWorkflowSnapshot(snapshot)
    setApprovalSubmissions({})
    if (!recordedWorkflowTasks.current.has(snapshot.taskId)) {
      recordedWorkflowTasks.current.add(snapshot.taskId)
      const newlyBlocked = snapshot.result.actions.filter(
        (action) => action.decision === 'BLOCK',
      ).length
      setDashboardStats((current) => ({
        ...current,
        blockedActions: current.blockedActions + newlyBlocked,
      }))
    }
    if (snapshot.result.actions.length > 0) {
      snapshot.result.actions.forEach((action) => {
        const isBlocked = action.decision === 'BLOCK'
        const needsReview = action.decision === 'APPROVE'
        addRecentActivity({
          icon: isBlocked ? '⛨' : needsReview ? '◷' : '✓',
          title: isBlocked ? 'Agent action blocked' : needsReview ? 'Approval required' : 'Agent action allowed',
          detail: `Policy decision for action ${action.action_id}`,
          tag: action.decision,
          color: isBlocked ? 'red' : needsReview ? 'amber' : 'green',
        })
      })
    } else {
      addRecentActivity({
        icon: '⌁',
        title: 'Agent workflow completed',
        detail: `Task ${snapshot.taskId} completed without tool actions`,
        tag: 'DONE',
        color: 'green',
      })
    }
  }

  function handleApprovalSubmitted(
    actionId: string,
    decision: 'approve' | 'reject',
  ) {
    setApprovalSubmissions((current) => ({ ...current, [actionId]: decision }))
    addRecentActivity({
      icon: '✓',
      title: `Approval ${decision === 'approve' ? 'granted' : 'rejected'}`,
      detail: `Decision submitted for action ${actionId}`,
      tag: decision === 'approve' ? 'APPROVED' : 'REJECTED',
      color: decision === 'approve' ? 'green' : 'red',
    })
  }

  const pendingApprovalCount = workflowSnapshot?.result.actions.filter(
    (action) => action.decision === 'APPROVE' && !approvalSubmissions[action.action_id],
  ).length ?? 0
  const [metricHistory, setMetricHistory] = useState<number[][]>([
    [0], [0], [0], [0],
  ])

  useEffect(() => {
    const currentCounts = [
      dashboardStats.protectedRequests,
      dashboardStats.maskedItems,
      dashboardStats.blockedActions,
      pendingApprovalCount,
    ]

    setMetricHistory((currentHistory) => {
      if (currentCounts.every((count, index) => currentHistory[index].at(-1) === count)) {
        return currentHistory
      }

      return currentHistory.map((series, index) =>
        [...series, currentCounts[index]].slice(-8),
      )
    })
  }, [dashboardStats.protectedRequests, dashboardStats.maskedItems, dashboardStats.blockedActions, pendingApprovalCount])

  return (
    <MotionConfig reducedMotion="user">
    <div className={`dark app-shell ${introActive ? 'intro-active' : ''}`}>
      <div className="ambient-background" aria-hidden="true">
        <span className="ambient-glow ambient-glow-one" />
        <span className="ambient-glow ambient-glow-two" />
        <span className="ambient-glow ambient-glow-three" />
      </div>
      {brandSplashVisible && (
        <div className="brand-splash" aria-label="AgentShield AI Security Platform">
          <div className="brand-splash-content">
            <div className="brand-splash-planet" aria-hidden="true">
              <span className="brand-planet-orbit orbit-back" />
              <span className="brand-planet-orbit orbit-front" />
              <span className="brand-planet-body" />
            </div>
            <h1>Agent<span>Shield</span></h1>
            <p>AI SECURITY PLATFORM</p>
          </div>
        </div>
      )}
      <aside className="sidebar">
        <a
          className="brand"
          href="#overview"
          onClick={() => {
            setIntroActive(false)
            setActivePage('Overview')
          }}
        >
          <span className="brand-mark">A</span>
          <span>
            agent<span className="brand-light">shield</span>
            <small>AI SECURITY PLATFORM</small>
          </span>
        </a>

        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navItems.map((item) => (
            <button
              key={item.label}
              className={`nav-item ${activePage === item.label ? 'active' : ''}`}
              onClick={() => {
                setIntroActive(false)
                setActivePage(item.label)
              }}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
              {item.label === 'Authorization' && pendingApprovalCount > 0 && (
                <span className="nav-count">{pendingApprovalCount}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="secure-card">
          <span className="secure-icon">◈</span>
            <div>
              <strong>AgentShield session</strong>
              <small>{privacySnapshot ? 'Privacy scan completed' : 'Run a scan to begin'}</small>
            </div>
          </div>
          <div className="profile">
            <div className="avatar">AS</div>
            <div>
              <strong>Workspace user</strong>
              <small>Current session</small>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{activePage}</strong>
          </div>
          <div className="top-actions">
            <span className="environment">
              <i /> LOCAL SESSION
            </span>
            <button
              className="icon-button"
              aria-label="Open audit logs"
              onClick={() => {
                setIntroActive(false)
                setActivePage('Audit Logs')
              }}
            >
              ▤
            </button>
            <div className="top-avatar">AS</div>
          </div>
        </header>

        <div className="page-content">
          <AnimatePresence mode="wait">
            <motion.div
              key={activePage}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25, ease: 'easeOut' }}
            >
              {activePage === 'AI Assistant' ? (
                <AssistantForm
                  onPrivacyComplete={handlePrivacyComplete}
                  onWorkflowComplete={handleWorkflowComplete}
                  onApprovalSubmitted={handleApprovalSubmitted}
                />
              ) : activePage === 'Privacy Guard' ? (
                <PrivacyGuardPage
                  snapshot={privacySnapshot}
                  comparison={privacyComparison}
                  onNewRequest={() => setActivePage('AI Assistant')}
                />
              ) : activePage === 'Agent Activity' ? (
                <AgentActivityPage
                  snapshot={workflowSnapshot}
                  comparison={privacyComparison}
                  onNewRequest={() => setActivePage('AI Assistant')}
                />
              ) : activePage === 'Authorization' ? (
                <AuthorizationPage
                  actions={workflowSnapshot?.result.actions ?? []}
                  resolvedDecisions={approvalSubmissions}
                  onApprovalSubmitted={handleApprovalSubmitted}
                  onNewRequest={() => setActivePage('AI Assistant')}
                />
              ) : activePage === 'Audit Logs' ? (
                <AuditLogs />
              ) : (
                <Dashboard
                  onNavigate={(page) => {
                    setIntroActive(false)
                    setActivePage(page)
                  }}
                  playIntro={introActive}
                  onIntroComplete={() => setIntroActive(false)}
                  stats={{ ...dashboardStats, pendingApprovals: pendingApprovalCount }}
                  recentActivity={recentActivity}
                  privacySnapshot={privacySnapshot}
                  workflowSnapshot={workflowSnapshot}
                  metricHistory={metricHistory}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
    </MotionConfig>
  )
}

export default App
