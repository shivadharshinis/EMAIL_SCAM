import { useState } from 'react'
import { api } from '../api/client.js'
import ForensicResult from '../components/ForensicResult.jsx'

export default function Analyze() {
  const [file, setFile] = useState(null)
  const [rawEml, setRawEml] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleAnalyze(event) {
    event.preventDefault()
    setError('')
    setResult(null)

    if (!file && !rawEml.trim()) {
      setError('Choose an .eml file or paste a raw email first.')
      return
    }

    setLoading(true)
    try {
      const analysis = file
        ? await api.analyzeFile(file)
        : await api.analyzeRaw(rawEml)
      setResult(analysis)
    } catch (err) {
      setError(err.message || 'Unable to analyze this email.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {result ? (
        <>
          <button
            type="button"
            onClick={() => setResult(null)}
            className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            Analyze another email
          </button>
          <ForensicResult analysis={result} />
        </>
      ) : (
        <section className="rounded-lg border border-slate-200 bg-white p-6">
          <h2 className="text-xl font-semibold">Analyze an email</h2>
          <p className="mt-2 text-sm text-slate-600">
            The uploaded email is analyzed through rule-based threat detection,
            machine-learning classification, header intelligence, infrastructure
            intelligence, campaign correlation, and the final risk scorer. URLs
            are extracted and analyzed as evidence only; they are never visited.
          </p>

          <form className="mt-6 space-y-5" onSubmit={handleAnalyze}>
            <label className="block">
              <span className="text-sm font-medium text-slate-800">.eml file</span>
              <input
                type="file"
                accept=".eml,.txt,message/rfc822,text/plain"
                className="mt-2 block w-full text-sm file:mr-4 file:rounded-md file:border-0 file:bg-indigo-50 file:px-3 file:py-2 file:text-indigo-700"
                onChange={(event) => setFile(event.target.files?.[0] || null)}
              />
            </label>

            <label className="block">
              <span className="text-sm font-medium text-slate-800">
                Or paste raw email
              </span>
              <textarea
                rows={12}
                value={rawEml}
                onChange={(event) => setRawEml(event.target.value)}
                placeholder="Paste RFC 822 / .eml text here"
                className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              />
            </label>

            {file && (
              <p className="text-sm text-slate-500">Selected file: {file.name}</p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-indigo-300"
            >
              {loading ? 'Analyzing…' : 'Analyze email'}
            </button>
          </form>

          {error && (
            <p role="alert" className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </p>
          )}
        </section>
      )}
    </div>
  )
}
