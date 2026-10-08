import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export default function Cases() {
  const [cases, setCases] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const loadCases = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setCases(await api.listAnalyses())
    } catch (err) {
      setError(err.message || 'Unable to load stored analyses.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadCases()
  }, [loadCases])

  return (
    <section className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wide text-indigo-700">Forensic workspace</p>
          <h2 className="mt-1 text-2xl font-semibold text-slate-900">Cases</h2>
          <p className="mt-2 text-sm text-slate-600">Stored analysis results available from the current backend session.</p>
        </div>
        <button
          type="button"
          onClick={loadCases}
          disabled={loading}
          className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <p>{error}</p>
          <p className="mt-2">
            If report access requires authentication, <Link className="font-medium underline" to="/login">sign in</Link> and retry.
          </p>
        </div>
      )}

      {loading ? (
        <p className="rounded-md border border-slate-200 bg-white p-5 text-sm text-slate-600">Loading stored analyses…</p>
      ) : cases.length ? (
        <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
          <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Analysis / File</th>
                <th className="px-4 py-3 font-medium">Sender / Subject</th>
                <th className="px-4 py-3 font-medium">Verdict</th>
                <th className="px-4 py-3 font-medium">Threat score</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Analyzed</th>
                <th className="px-4 py-3 font-medium"><span className="sr-only">Action</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {cases.map((item) => (
                <tr key={item.analysis_id} className="align-top hover:bg-slate-50">
                  <td className="max-w-56 px-4 py-3">
                    <p className="break-all font-mono text-xs text-slate-700">{item.analysis_id}</p>
                    <p className="mt-1 break-all text-slate-500">{item.filename || 'Raw email'}</p>
                  </td>
                  <td className="max-w-64 px-4 py-3">
                    <p className="break-all">{item.sender?.join(', ') || '—'}</p>
                    <p className="mt-1 break-words text-slate-500">{item.subject || 'No subject'}</p>
                  </td>
                  <td className="px-4 py-3 font-semibold">{item.verdict || item.prediction || '—'}</td>
                  <td className="px-4 py-3 tabular-nums">{item.threat_score ?? '—'} / 100</td>
                  <td className="px-4 py-3">{item.severity || '—'}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-slate-600">{formatDate(item.analyzed_at)}</td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/investigation/${encodeURIComponent(item.analysis_id)}`}
                      className="whitespace-nowrap rounded-md bg-indigo-600 px-3 py-2 text-xs font-semibold text-white hover:bg-indigo-700"
                    >
                      Investigate
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : !error ? (
        <div className="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center">
          <h3 className="font-semibold text-slate-900">No stored analyses</h3>
          <p className="mt-2 text-sm text-slate-600">Analyze an email to create a case in the current backend session.</p>
          <Link to="/analyze" className="mt-4 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700">
            Analyze an email
          </Link>
        </div>
      ) : null}
    </section>
  )
}
