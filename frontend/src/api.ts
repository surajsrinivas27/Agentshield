const API_BASE_URL =
    import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
    let response: Response

    try {
        response = await fetch(`${API_BASE_URL}${path}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        })
    } catch {
        throw new Error(
            `Cannot reach the AgentShield backend at ${API_BASE_URL}. Check that FastAPI is running and VITE_API_BASE_URL is correct.`,
        )
    }

    const responseText = await response.text()
    let data: unknown

    try {
        data = responseText ? JSON.parse(responseText) : null
    } catch {
        throw new Error('The backend returned an unreadable response.')
    }

    if (!response.ok) {
        const errorData = data as { detail?: string } | null
        throw new Error(errorData?.detail || `Request failed (${response.status})`)
    }

    return data as T
}

export type PrivacyEntity = {
    start: number
    end: number
    type: string
    confidence: number
}

export type PrivacyResponse = {
    request_id: string
    status: string
    entities: PrivacyEntity[]
}

export function analyzePrivacy(requestId: string, text: string) {
    return request<PrivacyResponse>('/api/privacy/analyze', {
        method: 'POST',
        body: JSON.stringify({ request_id: requestId, text }),
    })
}

export type WorkflowResponse = {
    task_id: string
    status: string
    assistant_response: string
    actions: {
        action_id: string
        decision: 'ALLOW' | 'BLOCK' | 'APPROVE'
        reason: string
    }[]
}

export function runWorkflow(body: {
    task_id: string
    user_task: string
    sanitized_content: string
    source: {
        source_id: string
        source_type: 'email' | 'document'
    }
}) {
    return request<WorkflowResponse>('/api/workflow/run', {
        method: 'POST',
        body: JSON.stringify(body),
    })
}

export function submitApproval(
    actionId: string,
    decision: 'approve' | 'reject',
) {
    return request(`/api/approval/${encodeURIComponent(actionId)}`, {
        method: 'POST',
        body: JSON.stringify({
            decision,
            reviewer_id: 'DEMO_REVIEWER',
        }),
    })
}

export type AuditLog = {
    action_id: string
    decision: string
    reason: string
    timestamp: string
}

export function getAuditLogs() {
    return request<{ logs: AuditLog[] }>('/api/audit/logs')
}
