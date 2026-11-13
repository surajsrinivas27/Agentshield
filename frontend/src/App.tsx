import { useEffect, useState, type FormEvent } from 'react'
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

const activity = [
  {
    icon: '✉',
    title: 'Email content scanned',
    detail: 'Sample activity · demo data',
    tag: 'SAMPLE',
    color: 'green',
  },
  {
    icon: '⌁',
    title: 'Agent requested CRM lookup',
    detail: 'Sample activity · demo data',
    tag: 'SAMPLE',
    color: 'amber',
  },
  {
    icon: '⛨',
    title: 'External instruction blocked',
    detail: 'Sample activity · demo data',
    tag: 'SAMPLE',
    color: 'red',
  },
]

function AssistantForm({
  onPrivacyComplete,
  onWorkflowComplete,
  onApprovalSubmitted,
}: {
  onPrivacyComplete: (snapshot: PrivacySnapshot) => void
  onWorkflowComplete: (snapshot: WorkflowSnapshot) => void
  onApprovalSubmitted: (actionId: string, decision: 'approve' | 'reject') => void
}) {
  const [task, setTask] = useState('')
  const [sourceType, setSourceType] = useState<'email' | 'document'>('email')
  const [sourceId, setSourceId] = useState('EMAIL_001')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [workflowLoading, setWorkflowLoading] = useState(false)
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
      })
      setHasAnalyzed(true)
    } catch (requestError) {
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
    } catch (requestError) {
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
              placeholder="EMAIL_001"
            />
          </div>
        </div>

        <label htmlFor="source-content">Email or document text</label>
        <textarea
          id="source-content"
          rows={8}
          value={content}
          onChange={(event) => setContent(event.target.value)}
          placeholder="Paste synthetic sample content here. Don’t use real personal data."
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
  chart,
}: {
  title: string
  value: string
  trend: string
  icon: string
  color: string
  chart: string
}) {
  return (
    <article className="metric-card">
      <div className="metric-head">
        <span>{title}</span>
        <span className={`metric-icon ${color}`}>{icon}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-foot">
        <span className={trend.startsWith('↗') ? 'trend' : 'attention'}>
          {trend}
        </span>
        <span>demo data</span>
      </div>
      <div className={`sparkline ${chart}`}>
        {Array.from({ length: 12 }, (_, index) => (
          <i key={index} />
        ))}
      </div>
    </article>
  )
}

function Dashboard({ onNavigate }: { onNavigate: (page: string) => void }) {
  return (
    <>
      <section className="welcome-row">
        <div>
          <div className="eyebrow">THURSDAY, NOVEMBER 13, 2026</div>
          <h1>Your agents, under control.</h1>
          <p className="subtitle">
            Keep sensitive data safe and every agent action accountable.
          </p>
          <span className="demo-data-tag">ILLUSTRATIVE DEMO DATA</span>
        </div>
        <button
          className="primary-button"
          onClick={() => onNavigate('AI Assistant')}
        >
          <span>＋</span> New secure request
        </button>
      </section>

      <section className="hero-panel">
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
        <div className="orb-wrap" aria-hidden="true">
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
        <div className="hero-foot">
          <span>
            <i /> PRIVACY LAYER ACTIVE
          </span>
          <span>
            LOCAL MASKING <b>·</b> POLICY CHECKS <b>·</b> AUDIT TRAIL
          </span>
        </div>
      </section>

      <section
        className="metrics-grid"
        aria-label="Illustrative demo security summary"
      >
        <Metric
          title="Requests protected"
          value="1,284"
          trend="↗ 12.8%"
          icon="✳"
          color="violet"
          chart="purple"
        />
        <Metric
          title="Sensitive items masked"
          value="3,719"
          trend="↗ 8.2%"
          icon="⬡"
          color="mint"
          chart="green"
        />
        <Metric
          title="Actions blocked"
          value="24"
          trend="This week"
          icon="⛨"
          color="coral"
          chart="red"
        />
        <Metric
          title="Awaiting approval"
          value="02"
          trend="Needs your review"
          icon="◷"
          color="gold"
          chart="gold"
        />
      </section>

      <section className="lower-grid">
        <article className="panel activity-panel">
          <div className="panel-heading">
            <div>
              <h3>Recent activity</h3>
              <p>Illustrative activity for the demo.</p>
            </div>
            <button
              className="text-button"
              onClick={() => onNavigate('Agent Activity')}
            >
              View all <span>→</span>
            </button>
          </div>
          <div className="activity-list">
            {activity.map((item) => (
              <div className="activity-row" key={item.title}>
                <div className={`activity-icon ${item.color}`}>{item.icon}</div>
                <div className="activity-text">
                  <strong>{item.title}</strong>
                  <small>{item.detail}</small>
                </div>
                <span className={`status ${item.color}`}>{item.tag}</span>
                <span className="row-arrow">›</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel posture-panel">
          <div className="panel-heading">
            <div>
              <h3>Security posture</h3>
              <p>Illustrative demo status.</p>
            </div>
            <span className="posture-ok">● DEMO</span>
          </div>
          <div className="posture-score">
            <div className="score-ring">
              <span>
                98<small>/100</small>
              </span>
            </div>
            <div>
              <strong>Sample score</strong>
              <p>
                Replace this with measured
                <br />
                backend results.
              </p>
            </div>
          </div>
          <div className="posture-items">
            <div>
              <span className="checkmark">✓</span> Privacy protection
              <strong>Sample</strong>
            </div>
            <div>
              <span className="checkmark">✓</span> Tool authorization
              <strong>Sample</strong>
            </div>
            <div>
              <span className="checkmark">✓</span> Audit logging
              <strong>Sample</strong>
            </div>
          </div>
        </article>
      </section>

      <footer className="page-footer">
        <span>
          AGENTSHIELD <b>·</b> KEEPING YOUR AI WORKFLOWS SAFE
        </span>
        <span>
          DEMO DASHBOARD <i />
        </span>
      </footer>
    </>
  )
}

function App() {
  const [activePage, setActivePage] = useState('Overview')
  const [privacySnapshot, setPrivacySnapshot] = useState<PrivacySnapshot | null>(null)
  const [workflowSnapshot, setWorkflowSnapshot] = useState<WorkflowSnapshot | null>(null)
  const [approvalSubmissions, setApprovalSubmissions] = useState<
    Record<string, 'approve' | 'reject'>
  >({})

  function handlePrivacyComplete(snapshot: PrivacySnapshot) {
    setPrivacySnapshot(snapshot)
    setWorkflowSnapshot(null)
    setApprovalSubmissions({})
  }

  function handleWorkflowComplete(snapshot: WorkflowSnapshot) {
    setWorkflowSnapshot(snapshot)
    setApprovalSubmissions({})
  }

  function handleApprovalSubmitted(
    actionId: string,
    decision: 'approve' | 'reject',
  ) {
    setApprovalSubmissions((current) => ({ ...current, [actionId]: decision }))
  }

  const pendingApprovalCount = workflowSnapshot?.result.actions.filter(
    (action) => action.decision === 'APPROVE' && !approvalSubmissions[action.action_id],
  ).length ?? 0

  return (
    <MotionConfig reducedMotion="user">
    <div className="dark app-shell">
      <aside className="sidebar">
        <a
          className="brand"
          href="#overview"
          onClick={() => setActivePage('Overview')}
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
              onClick={() => setActivePage(item.label)}
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
            <span className="secure-icon">✓</span>
            <div>
              <strong>Protection active</strong>
              <small>All systems operational</small>
            </div>
            <span className="live-dot" />
          </div>
          <div className="profile">
            <div className="avatar">CS</div>
            <div>
              <strong>Chandana S</strong>
              <small>Security admin</small>
            </div>
            <span className="more">···</span>
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
              <i /> PROTECTION ON
            </span>
            <button className="icon-button" aria-label="Notifications">
              ♧<b />
            </button>
            <div className="top-avatar">CS</div>
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
                  onNewRequest={() => setActivePage('AI Assistant')}
                />
              ) : activePage === 'Agent Activity' ? (
                <AgentActivityPage
                  snapshot={workflowSnapshot}
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
                <Dashboard onNavigate={setActivePage} />
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
