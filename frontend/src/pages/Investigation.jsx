import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client.js'
import ForensicResult from '../components/ForensicResult.jsx'

export default function Investigation() {
  const { id } = useParams()
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(Boolean(id))

  useEffect(() => {
    let active = true
    if (!id) {
      setLoading(false)
      return () => {
        active = false
      }
    }

    setLoading(true)
    setError('')
    api.getAnalysis(id)
      .then((result) => {
        if (active) setAnalysis(result)
      })
      .catch((err) => {
        if (active) setError(err.message || 'Unable to load this stored analysis.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [id])

  if (!id) {
    return (
      <section className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 className="text-xl font-semibold">Investigation</h2>
        <p className="mt-2 text-slate-600">Select a stored case to review its forensic analysis.</p>
        <Link to="/cases" className="mt-4 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700">
          Browse cases
        </Link>
      </section>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link to="/cases" className="text-sm font-medium text-indigo-700 hover:underline">← Back to Cases</Link>
          <h2 className="mt-2 text-2xl font-semibold text-slate-900">Investigation</h2>
          <p className="mt-1 break-all font-mono text-xs text-slate-500">Analysis ID: {id}</p>
        </div>
      </div>

      {loading && <p className="rounded-md border border-slate-200 bg-white p-5 text-sm text-slate-600">Loading analysis…</p>}
      {error && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <p>{error}</p>
          <p className="mt-2">
            The analysis may not be available in this backend session, or authentication may be required.{' '}
            <Link className="font-medium underline" to="/login">Sign in</Link> or <Link className="font-medium underline" to="/cases">return to Cases</Link>.
          </p>
        </div>
      )}
      {analysis && <ForensicResult analysis={analysis} />}
    </div>
  )
}
