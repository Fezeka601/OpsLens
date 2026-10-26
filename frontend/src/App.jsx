import { useEffect, useState } from 'react'
import './App.css'

const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

const RESPONSE_STATUSES = [
  'UNDER_REVIEW',
  'APPROVED',
  'COMPLETED',
]

function App() {
  const [activePage, setActivePage] = useState('Overview')
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [investigations, setInvestigations] = useState([])
  const [investigating, setInvestigating] = useState(false)
  const [investigationMessage, setInvestigationMessage] = useState('')

  const [responseActions, setResponseActions] = useState([])
  const [loadingActions, setLoadingActions] = useState(false)
  const [updatingActionId, setUpdatingActionId] = useState(null)
  const [actionMessage, setActionMessage] = useState('')
  const [actionError, setActionError] = useState('')

  async function loadDashboard() {
    try {
      setLoading(true)
      setError('')

      const [alertsResponse, incidentsResponse] = await Promise.all([
        fetch(`${API_URL}/alerts?limit=100`),
        fetch(`${API_URL}/incidents?limit=100`),
      ])

      if (!alertsResponse.ok || !incidentsResponse.ok) {
        throw new Error('The API could not load alerts or incidents.')
      }

      const alertsData = await alertsResponse.json()
      const incidentsData = await incidentsResponse.json()

      setAlerts(
        Array.isArray(alertsData) ? alertsData : alertsData.alerts ?? [],
      )

      setIncidents(
        Array.isArray(incidentsData)
          ? incidentsData
          : incidentsData.incidents ?? [],
      )
    } catch (err) {
      setError(
        `${err.message} Make sure the OpsLens FastAPI backend is running.`,
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDashboard()
  }, [])

  const openIncidents = incidents.filter(
    (incident) => incident.status === 'OPEN',
  )

  const highSeverityIncidents = incidents.filter(
    (incident) =>
      incident.severity === 'HIGH' || incident.severity === 'CRITICAL',
  )

  async function investigateIncident(incident) {
    const incidentId = incident.incident_id

    if (!incidentId) {
      setError('This incident has no incident ID.')
      return
    }

    setSelectedIncident(incident)
    setActivePage('Incidents')
    setInvestigations([])
    setInvestigationMessage('')
    setResponseActions([])
    setActionMessage('')
    setActionError('')
    setError('')
    setInvestigating(true)

    try {
      const runResponse = await fetch(
        `${API_URL}/incidents/${encodeURIComponent(incidentId)}/investigation`,
        { method: 'POST' },
      )

      const runData = await runResponse.json().catch(() => ({}))

      if (!runResponse.ok) {
        throw new Error(
          runData.detail ||
            runData.message ||
            'The investigation could not run.',
        )
      }

      setInvestigationMessage('Investigation completed successfully.')

      const historyResponse = await fetch(
        `${API_URL}/incidents/${encodeURIComponent(incidentId)}/investigation`,
      )

      const historyData = await historyResponse.json().catch(() => ({}))

      if (!historyResponse.ok) {
        setInvestigations([runData])
        setInvestigationMessage(
          'Investigation completed. Could not retrieve saved investigation history.',
        )
      } else {
        const savedInvestigations = Array.isArray(
          historyData.investigations,
        )
          ? historyData.investigations
          : []

        setInvestigations(
          savedInvestigations.length > 0 ? savedInvestigations : [runData],
        )
      }
    } catch (err) {
      setError(err.message || 'An unexpected investigation error occurred.')
    } finally {
      setInvestigating(false)
    }

    await loadResponseActions(incidentId)
  }

  async function loadResponseActions(incidentId) {
    if (!incidentId) return

    setLoadingActions(true)
    setActionError('')
    setActionMessage('')

    try {
      const response = await fetch(
        `${API_URL}/incidents/${encodeURIComponent(incidentId)}/response-actions`,
      )

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          data.detail || data.message || 'Could not load response actions.',
        )
      }

      setResponseActions(Array.isArray(data.actions) ? data.actions : [])
    } catch (err) {
      setActionError(err.message || 'Could not load response actions.')
      setResponseActions([])
    } finally {
      setLoadingActions(false)
    }
  }

  function getResponseActionId(action) {
    return (
      action.response_action_id ??
      action.action_id ??
      action.id ??
      action.response_id ??
      null
    )
  }

  async function updateResponseAction(action, newStatus) {
    const incidentId = selectedIncident?.incident_id
    const actionId = getResponseActionId(action)

    if (!incidentId || !actionId) {
      setActionError(
        'The incident or response action ID is missing. Check the API response.',
      )
      return
    }

    setUpdatingActionId(String(actionId))
    setActionError('')
    setActionMessage('')

    try {
      const response = await fetch(
        `${API_URL}/incidents/${encodeURIComponent(incidentId)}/response-actions/${encodeURIComponent(actionId)}/status`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ status: newStatus }),
        },
      )

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          data.detail || data.message || 'Could not update response action.',
        )
      }

      setActionMessage(
        `Response action status updated to ${newStatus}.`,
      )

      // Reload from the API to confirm the saved status.
      await loadResponseActions(incidentId)
    } catch (err) {
      setActionError(err.message || 'Could not update response action.')
    } finally {
      setUpdatingActionId(null)
    }
  }

  const navigation = [
    { name: 'Overview', icon: '◫' },
    { name: 'Alerts', icon: '⌁' },
    { name: 'Incidents', icon: '◈' },
  ]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">O</div>
          <div>
            <h1>OpsLens</h1>
            <p>SECURITY OPERATIONS</p>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav>
          {navigation.map((item) => (
            <button
              className={`nav-item ${activePage === item.name ? 'active' : ''}`}
              key={item.name}
              onClick={() => setActivePage(item.name)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.name}
              {item.name === 'Alerts' && (
                <span className="nav-count">{alerts.length}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-indicator">
            <span className="status-dot" />
            <div>
              <strong>System status</strong>
              <span>{error ? 'Connection issue' : 'Monitoring dashboard'}</span>
            </div>
          </div>
          <p className="sidebar-version">OPSLENS · DEVELOPMENT</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace / </span>
            <strong>{activePage}</strong>
          </div>
          <div className="topbar-right">
            <span className="live-indicator">
              <span className="status-dot" />
              LOCAL ENVIRONMENT
            </span>
            <div className="avatar">OL</div>
          </div>
        </header>

        <section className="page-content">
          <div className="page-heading">
            <div>
              <p className="eyebrow">SECURITY INTELLIGENCE</p>
              <h2>{activePage}</h2>
              <p className="page-description">
                Monitor threats, investigate incidents, and review security
                activity.
              </p>
            </div>
            <button className="refresh-button" onClick={loadDashboard}>
              ↻ Refresh data
            </button>
          </div>

          {error && <div className="error-banner">{error}</div>}

          {loading ? (
            <div className="loading-panel">Loading security data...</div>
          ) : (
            <>
              {activePage === 'Overview' && (
                <>
                  <div className="section-heading">
                    <h3>Security overview</h3>
                    <span>Data from your OpsLens API</span>
                  </div>

                  <div className="stats-grid">
                    <StatCard
                      label="Total alerts"
                      value={alerts.length}
                      note="Retrieved from API"
                      icon="⌁"
                      variant="blue"
                    />
                    <StatCard
                      label="Total incidents"
                      value={incidents.length}
                      note="Tracked incidents"
                      icon="◈"
                      variant="purple"
                    />
                    <StatCard
                      label="Open incidents"
                      value={openIncidents.length}
                      note="Require review"
                      icon="◎"
                      variant="orange"
                    />
                    <StatCard
                      label="High / critical"
                      value={highSeverityIncidents.length}
                      note="Elevated severity"
                      icon="△"
                      variant="red"
                    />
                  </div>

                  <div className="content-grid">
                    <section className="panel">
                      <div className="panel-heading">
                        <div>
                          <h3>Recent incidents</h3>
                          <p>Choose an incident to investigate</p>
                        </div>
                        <button
                          className="text-button"
                          onClick={() => setActivePage('Incidents')}
                        >
                          View all →
                        </button>
                      </div>
                      <IncidentTable
                        incidents={incidents.slice(0, 5)}
                        onInvestigate={investigateIncident}
                      />
                    </section>

                    <section className="panel activity-panel">
                      <div className="panel-heading">
                        <div>
                          <h3>Alert overview</h3>
                          <p>Severity distribution</p>
                        </div>
                      </div>
                      <SeveritySummary alerts={alerts} />
                    </section>
                  </div>
                </>
              )}

              {activePage === 'Alerts' && (
                <section className="panel full-panel">
                  <div className="panel-heading">
                    <div>
                      <h3>Security alerts</h3>
                      <p>{alerts.length} alerts returned by the API</p>
                    </div>
                  </div>
                  <AlertTable alerts={alerts} />
                </section>
              )}

              {activePage === 'Incidents' && (
                <>
                  <section className="panel full-panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Security incidents</h3>
                        <p>
                          {incidents.length} incidents returned by the API.
                          Select Investigate to run an analysis.
                        </p>
                      </div>
                    </div>
                    <IncidentTable
                      incidents={incidents}
                      onInvestigate={investigateIncident}
                    />
                  </section>

                  {selectedIncident && (
                    <>
                      <section className="panel full-panel investigation-panel">
                        <div className="panel-heading">
                          <div>
                            <p className="eyebrow">INCIDENT ANALYSIS</p>
                            <h3>
                              {selectedIncident.title || 'Incident investigation'}
                            </h3>
                            <p className="cell-subtext">
                              {selectedIncident.incident_id}
                            </p>
                          </div>
                          <SeverityBadge
                            severity={selectedIncident.severity}
                          />
                        </div>

                        {investigating && (
                          <div className="loading-panel">
                            Running investigation and retrieving saved results...
                          </div>
                        )}

                        {investigationMessage && (
                          <div className="success-banner">
                            {investigationMessage}
                          </div>
                        )}

                        {!investigating &&
                          investigations.length === 0 &&
                          !error && (
                            <p className="empty-state">
                              No investigation results to display yet.
                            </p>
                          )}

                        {investigations.map((result, index) => (
                          <InvestigationResult
                            key={
                              result.investigation_id ||
                              result.id ||
                              `${selectedIncident.incident_id}-${index}`
                            }
                            result={result}
                            index={index}
                          />
                        ))}
                      </section>

                      <section className="panel full-panel response-actions-panel">
                        <div className="panel-heading">
                          <div>
                            <p className="eyebrow">INCIDENT RESPONSE</p>
                            <h3>Recommended response actions</h3>
                            <p>
                              Review actions and update their workflow status.
                            </p>
                          </div>
                          <button
                            className="refresh-button"
                            onClick={() =>
                              loadResponseActions(selectedIncident.incident_id)
                            }
                            disabled={loadingActions}
                          >
                            ↻ Refresh actions
                          </button>
                        </div>

                        {actionMessage && (
                          <div className="success-banner">{actionMessage}</div>
                        )}

                        {actionError && (
                          <div className="error-banner">{actionError}</div>
                        )}

                        {loadingActions ? (
                          <div className="loading-panel">
                            Loading response actions...
                          </div>
                        ) : responseActions.length === 0 ? (
                          <p className="empty-state">
                            No response actions were returned for this incident.
                          </p>
                        ) : (
                          <ResponseActionList
                            actions={responseActions}
                            updatingActionId={updatingActionId}
                            onUpdate={updateResponseAction}
                          />
                        )}
                      </section>
                    </>
                  )}
                </>
              )}
            </>
          )}

          <footer className="page-footer">
            <span>OpsLens Security Monitoring</span>
            <span>FastAPI · React · PostgreSQL</span>
          </footer>
        </section>
      </main>
    </div>
  )
}

function StatCard({ label, value, note, icon, variant }) {
  return (
    <article className="stat-card">
      <div className={`stat-icon ${variant}`}>{icon}</div>
      <p className="stat-label">{label}</p>
      <div className="stat-value">{value}</div>
      <p className="stat-note">{note}</p>
    </article>
  )
}

function SeverityBadge({ severity }) {
  const normalized = (severity || 'UNKNOWN').toUpperCase()
  const style = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)
    ? normalized.toLowerCase()
    : 'unknown'

  return <span className={`severity-badge ${style}`}>{normalized}</span>
}

function IncidentTable({ incidents, onInvestigate }) {
  if (incidents.length === 0) {
    return <div className="empty-state">No incidents found.</div>
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>INCIDENT</th>
            <th>SEVERITY</th>
            <th>STATUS</th>
            <th>USER</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident, index) => (
            <tr key={incident.incident_id || index}>
              <td>
                <strong>{incident.title || 'Untitled incident'}</strong>
                <span className="cell-subtext">
                  {incident.incident_id || 'No ID'}
                </span>
              </td>
              <td>
                <SeverityBadge severity={incident.severity} />
              </td>
              <td>
                <span
                  className={`status-badge ${(incident.status || 'unknown').toLowerCase()}`}
                >
                  {incident.status || 'UNKNOWN'}
                </span>
              </td>
              <td>{incident.user_id || '—'}</td>
              <td>
                <button
                  className="investigate-button"
                  onClick={() => onInvestigate(incident)}
                  disabled={!incident.incident_id}
                >
                  Investigate →
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertTable({ alerts }) {
  if (alerts.length === 0) {
    return <div className="empty-state">No alerts found.</div>
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>DETECTION RULE</th>
            <th>SEVERITY</th>
            <th>MESSAGE</th>
            <th>ALERT ID</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => (
            <tr key={alert.alert_id || index}>
              <td>
                <strong>{alert.rule || 'Security alert'}</strong>
              </td>
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td>{alert.message || 'No message provided'}</td>
              <td className="id-cell">{alert.alert_id || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SeveritySummary({ alerts }) {
  const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const total = alerts.length

  return (
    <div className="severity-summary">
      {levels.map((level) => {
        const count = alerts.filter(
          (alert) => (alert.severity || '').toUpperCase() === level,
        ).length
        const percentage = total ? (count / total) * 100 : 0

        return (
          <div className="severity-row" key={level}>
            <div className="severity-label">
              <span>{level}</span>
              <strong>{count}</strong>
            </div>
            <div className="progress-track">
              <div
                className={`progress-fill ${level.toLowerCase()}`}
                style={{ width: `${percentage}%` }}
              />
            </div>
          </div>
        )
      })}
      <p className="summary-footnote">
        Severity counts are calculated from the alerts currently loaded.
      </p>
    </div>
  )
}

function InvestigationResult({ result, index }) {
  const excludedKeys = new Set(['investigation_id', 'id', 'incident_id'])

  return (
    <article className="investigation-result">
      <div className="investigation-result-heading">
        <h4>Investigation result {index + 1}</h4>
        {result.investigation_id && (
          <span className="cell-subtext">
            ID: {String(result.investigation_id)}
          </span>
        )}
      </div>

      {Object.entries(result)
        .filter(([key]) => !excludedKeys.has(key))
        .map(([key, value]) => (
          <div className="investigation-field" key={key}>
            <strong>{formatLabel(key)}</strong>
            <div>
              {value === null || value === undefined ? (
                '—'
              ) : typeof value === 'object' ? (
                <pre>{JSON.stringify(value, null, 2)}</pre>
              ) : (
                String(value)
              )}
            </div>
          </div>
        ))}
    </article>
  )
}

function ResponseActionList({ actions, updatingActionId, onUpdate }) {
  return (
    <div className="response-action-list">
      {actions.map((action, index) => {
        const actionId =
          action.response_action_id ??
          action.action_id ??
          action.id ??
          action.response_id ??
          `action-${index}`

        const status = String(action.status || 'UNDER_REVIEW').toUpperCase()
        const busy = updatingActionId === String(actionId)

        return (
          <article className="response-action-card" key={String(actionId)}>
            <div className="response-action-heading">
              <div>
                <h4>
                  {formatLabel(
                    String(
                      action.action ??
                        action.action_type ??
                        action.name ??
                        'Security response action',
                    ),
                  )}
                </h4>
                <p className="cell-subtext">
                  Action ID: {String(actionId)}
                </p>
              </div>
              <span
                className={`status-badge ${status.toLowerCase()}`}
              >
                {status.replaceAll('_', ' ')}
              </span>
            </div>

            {Object.entries(action)
              .filter(
                ([key]) =>
                  ![
                    'response_action_id',
                    'action_id',
                    'id',
                    'response_id',
                    'status',
                    'action',
                    'action_type',
                    'name',
                  ].includes(key),
              )
              .map(([key, value]) => (
                <div className="response-action-detail" key={key}>
                  <strong>{formatLabel(key)}</strong>
                  <span>
                    {value === null || value === undefined
                      ? '—'
                      : typeof value === 'object'
                        ? JSON.stringify(value)
                        : String(value)}
                  </span>
                </div>
              ))}

            <div className="response-action-controls">
              <label htmlFor={`status-${String(actionId)}`}>
                Update status
              </label>
              <select
                id={`status-${String(actionId)}`}
                value={RESPONSE_STATUSES.includes(status) ? status : 'UNDER_REVIEW'}
                disabled={busy}
                onChange={(event) => onUpdate(action, event.target.value)}
              >
                {RESPONSE_STATUSES.map((option) => (
                  <option key={option} value={option}>
                    {option.replaceAll('_', ' ')}
                  </option>
                ))}
              </select>
              {busy && <span>Saving...</span>}
            </div>
          </article>
        )
      })}
    </div>
  )
}

function formatLabel(value) {
  return value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

export default App