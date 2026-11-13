import { useState, type ReactNode } from 'react'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Clock3,
  FileSearch,
  LockKeyhole,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { submitApproval, type WorkflowResponse } from './api'

export type PrivacySnapshot = {
  total: number
  entityCounts: Record<string, number>
  sourceId: string
  sourceType: 'email' | 'document'
  checkedAt: string
}

export type WorkflowSnapshot = {
  result: WorkflowResponse
  taskId: string
  sourceId: string
  sourceType: 'email' | 'document'
}

function PageHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <header className="feature-heading">
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      <p className="subtitle">{description}</p>
    </header>
  )
}

function EmptyState({
  icon,
  title,
  detail,
  onNewRequest,
}: {
  icon: ReactNode
  title: string
  detail: string
  onNewRequest: () => void
}) {
  return (
    <Card className="feature-card feature-empty">
      <CardContent>
        <div className="feature-empty-icon">{icon}</div>
        <h2>{title}</h2>
        <p>{detail}</p>
        <Button className="feature-button" onClick={onNewRequest}>
          Open AI Assistant <ArrowRight aria-hidden="true" />
        </Button>
      </CardContent>
    </Card>
  )
}

export function PrivacyGuardPage({
  snapshot,
  onNewRequest,
}: {
  snapshot: PrivacySnapshot | null
  onNewRequest: () => void
}) {
  return (
    <section className="feature-screen">
      <PageHeading
        eyebrow="DATA PROTECTION"
        title="Privacy Guard"
        description="Review what was detected and masked before a task reached the agent."
      />

      {!snapshot ? (
        <EmptyState
          icon={<FileSearch aria-hidden="true" />}
          title="No privacy scan in this session"
          detail="Start a secure request to run the privacy analysis. Only entity types and counts are shown here; original values stay in the assistant screen’s memory."
          onNewRequest={onNewRequest}
        />
      ) : (
        <motion.div
          className="feature-grid"
          initial="hidden"
          animate="visible"
          variants={{ visible: { transition: { staggerChildren: 0.08 } } }}
        >
          <motion.div variants={featureItem}>
            <Card className="feature-card summary-card">
              <CardHeader>
                <div className="feature-icon violet"><ShieldCheck /></div>
                <CardTitle>Items masked locally</CardTitle>
                <CardDescription>Latest completed privacy check</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="feature-stat">{snapshot.total}</div>
                <p className="feature-meta">
                  Source: {snapshot.sourceId} · {snapshot.sourceType}
                </p>
                <p className="feature-meta">
                  Checked {new Date(snapshot.checkedAt).toLocaleString()}
                </p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={featureItem}>
            <Card className="feature-card summary-card">
              <CardHeader>
                <div className="feature-icon mint"><LockKeyhole /></div>
                <CardTitle>Detected entity types</CardTitle>
                <CardDescription>
                  Counts only; original values are not shown here
                </CardDescription>
              </CardHeader>
              <CardContent>
                {Object.keys(snapshot.entityCounts).length ? (
                  <ul className="entity-count-list">
                    {Object.entries(snapshot.entityCounts).map(([type, count]) => (
                      <li key={type}>
                        <span>{type.replaceAll('_', ' ')}</span>
                        <strong>{count}</strong>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="feature-meta">No sensitive entities detected.</p>
                )}
              </CardContent>
            </Card>
          </motion.div>

          <motion.div className="feature-wide" variants={featureItem}>
            <Card className="feature-card privacy-note-card">
              <CardContent>
                <div className="feature-note-icon"><ShieldAlert /></div>
                <div>
                  <h2>Local masking is active</h2>
                  <p>
                    The browser replaced detected spans before sending the
                    sanitized content to the agent workflow. The placeholder
                    mapping remains in memory in the AI Assistant and is not
                    sent to Sarvam AI.
                  </p>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </motion.div>
      )}
    </section>
  )
}

const featureItem = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.28, ease: 'easeOut' as const },
  },
}

export function AgentActivityPage({
  snapshot,
  onNewRequest,
}: {
  snapshot: WorkflowSnapshot | null
  onNewRequest: () => void
}) {
  return (
    <section className="feature-screen">
      <PageHeading
        eyebrow="WORKFLOW PROVENANCE"
        title="Agent Activity"
        description="See the latest agent decisions alongside the source and task that produced them."
      />

      {!snapshot ? (
        <EmptyState
          icon={<Activity aria-hidden="true" />}
          title="No agent activity yet"
          detail="Run a secure request to see workflow actions and their decisions here."
          onNewRequest={onNewRequest}
        />
      ) : (
        <>
          <Card className="feature-card provenance-card">
            <CardHeader>
              <CardTitle>Latest run context</CardTitle>
              <CardDescription>
                Source metadata and actions from the latest workflow response
              </CardDescription>
            </CardHeader>
            <CardContent className="provenance-grid">
              <div><span>Task</span><strong>{snapshot.taskId}</strong></div>
              <div><span>Source</span><strong>{snapshot.sourceId}</strong></div>
              <div><span>Source type</span><strong>{snapshot.sourceType}</strong></div>
              <div><span>Workflow status</span><strong>{snapshot.result.status}</strong></div>
            </CardContent>
          </Card>

          <div className="activity-timeline">
            <AnimatePresence initial={false}>
              {snapshot.result.actions.map((action, index) => (
                <motion.article
                  className="feature-card timeline-card"
                  key={action.action_id}
                  initial={{ opacity: 0, x: 12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: index * 0.06 }}
                >
                  <div className={`timeline-icon ${action.decision.toLowerCase()}`}>
                    {action.decision === 'ALLOW' ? <CheckCircle2 /> :
                      action.decision === 'BLOCK' ? <ShieldAlert /> : <Clock3 />}
                  </div>
                  <div className="timeline-copy">
                    <div className="timeline-title-row">
                      <strong>{action.action_id}</strong>
                      <span className={`audit-decision ${action.decision.toLowerCase()}`}>
                        {action.decision}
                      </span>
                    </div>
                    <p>{action.reason}</p>
                    <small>Source {snapshot.sourceId} · {snapshot.sourceType}</small>
                  </div>
                </motion.article>
              ))}
            </AnimatePresence>
            {snapshot.result.actions.length === 0 && (
              <Card className="feature-card"><CardContent><p className="feature-meta">The workflow returned no proposed actions.</p></CardContent></Card>
            )}
          </div>
        </>
      )}
    </section>
  )
}

export function AuthorizationPage({
  actions,
  resolvedDecisions,
  onApprovalSubmitted,
  onNewRequest,
}: {
  actions: WorkflowResponse['actions']
  resolvedDecisions: Record<string, 'approve' | 'reject'>
  onApprovalSubmitted: (actionId: string, decision: 'approve' | 'reject') => void
  onNewRequest: () => void
}) {
  const [loadingId, setLoadingId] = useState<string | null>(null)
  const [messages, setMessages] = useState<Record<string, string>>({})
  const [errors, setErrors] = useState<Record<string, string>>({})
  const pending = actions.filter(
    (action) => action.decision === 'APPROVE' && !resolvedDecisions[action.action_id],
  )
  const resolved = actions.filter((action) => resolvedDecisions[action.action_id])

  async function decide(actionId: string, decision: 'approve' | 'reject') {
    setLoadingId(actionId)
    setErrors((current) => ({ ...current, [actionId]: '' }))
    setMessages((current) => ({ ...current, [actionId]: '' }))

    try {
      await submitApproval(actionId, decision)
      onApprovalSubmitted(actionId, decision)
      setMessages((current) => ({
        ...current,
        [actionId]: `Your ${decision} decision was submitted.`,
      }))
    } catch (error) {
      setErrors((current) => ({
        ...current,
        [actionId]: error instanceof Error ? error.message : 'Could not submit your decision.',
      }))
    } finally {
      setLoadingId(null)
    }
  }

  return (
    <section className="feature-screen">
      <PageHeading
        eyebrow="POLICY AND HUMAN REVIEW"
        title="Authorization Center"
        description="Review actions marked for human approval. ALLOW and BLOCK decisions are determined by the backend policy gateway."
      />

      {!actions.length ? (
        <EmptyState
          icon={<LockKeyhole aria-hidden="true" />}
          title="No authorization decisions yet"
          detail="Submit a secure request to see the backend's ALLOW, BLOCK, and APPROVE decisions here."
          onNewRequest={onNewRequest}
        />
      ) : (
        <div className="authorization-list">
          <Card className="feature-card authorization-summary">
            <CardContent>
              <div className="decision-summary"><CheckCircle2 /><span>Allowed</span><strong>{actions.filter((action) => action.decision === 'ALLOW').length}</strong></div>
              <div className="decision-summary"><ShieldAlert /><span>Blocked</span><strong>{actions.filter((action) => action.decision === 'BLOCK').length}</strong></div>
              <div className="decision-summary"><Clock3 /><span>Needs review</span><strong>{pending.length}</strong></div>
            </CardContent>
          </Card>

          {pending.length ? pending.map((action) => (
            <Card className="feature-card approval-card" key={action.action_id}>
              <CardHeader>
                <div className="approval-card-heading">
                  <div className="feature-icon gold"><Clock3 /></div>
                  <span className="audit-decision approve">APPROVAL REQUIRED</span>
                </div>
                <CardTitle>{action.action_id}</CardTitle>
                <CardDescription>{action.reason}</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="approval-warning">Review the proposed action and reason before submitting your decision.</p>
                <div className="approval-actions">
                  <Button
                    className="feature-button"
                    disabled={loadingId === action.action_id}
                    onClick={() => decide(action.action_id, 'approve')}
                  >
                    {loadingId === action.action_id ? 'Submitting…' : 'Approve action'}
                  </Button>
                  <Button
                    variant="outline"
                    className="feature-button reject-button"
                    disabled={loadingId === action.action_id}
                    onClick={() => decide(action.action_id, 'reject')}
                  >
                    Reject
                  </Button>
                </div>
                {messages[action.action_id] && <p className="feature-success" role="status">{messages[action.action_id]}</p>}
                {errors[action.action_id] && <p className="assistant-error" role="alert">{errors[action.action_id]}</p>}
              </CardContent>
            </Card>
          )) : (
            <Card className="feature-card"><CardContent className="review-clear"><ShieldCheck /><div><strong>No actions are waiting for human review.</strong><p>Only workflow actions with an APPROVE decision appear here.</p></div></CardContent></Card>
          )}
          {resolved.map((action) => (
            <Card className="feature-card" key={`resolved-${action.action_id}`}>
              <CardContent className="review-clear">
                <CheckCircle2 />
                <div>
                  <strong>{action.action_id}: {resolvedDecisions[action.action_id]} decision submitted</strong>
                  <p>The backend remains responsible for revalidating policy before execution.</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </section>
  )
}
