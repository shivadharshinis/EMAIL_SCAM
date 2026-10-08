import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'

function Section({ title, children, className = '' }) {
  return (
    <section className={`rounded-lg border border-slate-200 bg-white p-5 ${className}`}>
      <h3 className="text-base font-semibold text-slate-900">{title}</h3>
      <div className="mt-3 text-sm text-slate-700">{children}</div>
    </section>
  )
}

function EmptyValue({ text = 'None found' }) {
  return <p className="text-slate-500">{text}</p>
}

function ItemList({ items, renderItem = (item) => item, emptyText }) {
  if (!items?.length) {
    return <EmptyValue text={emptyText} />
  }
  return (
    <ul className="space-y-2 break-all">
      {items.map((item, index) => (
        <li key={`${typeof item === 'string' ? item : JSON.stringify(item)}-${index}`}>
          {renderItem(item)}
        </li>
      ))}
    </ul>
  )
}

function Value({ children, className = '' }) {
  return <dd className={`break-words font-medium text-slate-900 ${className}`}>{children || '—'}</dd>
}

function Field({ label, children, className = '' }) {
  return (
    <div className={className}>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <Value>{children}</Value>
    </div>
  )
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatLabel(value) {
  if (!value) return '—'
  return value.toLowerCase().replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function senderDomains(domains = [], source) {
  return domains.filter((item) => item.source?.startsWith(source))
}

function isIpLiteral(hostname = '') {
  const host = hostname.replace(/^\[|\]$/g, '')
  const ipv4Parts = host.split('.')
  const isIpv4 = ipv4Parts.length === 4 && ipv4Parts.every(
    (part) => /^\d{1,3}$/.test(part) && Number(part) <= 255,
  )
  return isIpv4 || host.includes(':')
}

function Metric({ label, value }) {
  return (
    <div className="rounded-md bg-slate-50 p-3">
      <dt className="text-xs font-medium uppercase text-slate-500">{label}</dt>
      <dd className="mt-1 text-lg font-semibold text-slate-900">
        {typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '—'}
      </dd>
    </div>
  )
}

export default function ForensicResult({ analysis }) {
  const [modelInfo, setModelInfo] = useState(null)
  const [modelInfoError, setModelInfoError] = useState('')
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError, setReportError] = useState('')

  useEffect(() => {
    let active = true
    api.modelInfo()
      .then((info) => {
        if (active) setModelInfo(info)
      })
      .catch((error) => {
        if (active) setModelInfoError(error.message || 'Model information is unavailable.')
      })
    return () => {
      active = false
    }
  }, [])

  async function handleDownloadReport() {
    if (!analysis.analysis_id) return
    setReportError('')
    setReportLoading(true)
    try {
      const blob = await api.downloadReport(analysis.analysis_id)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `email_forensic_report_${analysis.analysis_id}.pdf`
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      setReportError(error.message || 'Unable to download the forensic report.')
    } finally {
      setReportLoading(false)
    }
  }

  const message = analysis.message || {}
  const headers = analysis.headers || {}
  const threat = analysis.threat_detection || {}
  const ml = analysis.ml_detection || {}
  const risk = analysis.final_risk || {}
  const headerInfo = analysis.header_intelligence || {}
  const domains = headerInfo.domains || []
  const suspiciousDomains = domains.filter((domain) => domain.is_punycode || domain.is_ip_literal)
  const ipLiteralUrls = (analysis.urls || []).filter((item) => isIpLiteral(item.hostname))
  const verdictStyle = risk.verdict === 'MALICIOUS'
    ? 'border-red-200 bg-red-50 text-red-900'
    : 'border-emerald-200 bg-emerald-50 text-emerald-900'

  return (
    <div className="space-y-4">
      <Section title="1. Final Threat Assessment" className={`border-2 ${verdictStyle}`}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Verdict">{risk.verdict || '—'}</Field>
          <Field label="Threat score">{risk.score ?? '—'} / 100</Field>
          <Field label="Threat level">{risk.severity || '—'}</Field>
          <Field label="Confidence">{risk.confidence || '—'}</Field>
        </div>
        <p className="mt-4 text-base font-medium">{risk.explanation || 'No final risk explanation was returned.'}</p>
        <p className="mt-2 text-xs opacity-80">
          This is the backend&apos;s combined final risk result; the UI does not recalculate the score.
        </p>
      </Section>

      <Section title="2. Email Metadata">
        <dl className="grid gap-4 sm:grid-cols-2">
          <Field label="Analysis ID">{analysis.analysis_id}</Field>
          <Field label="Filename">{analysis.filename}</Field>
          <Field label="Subject">{message.subject}</Field>
          <Field label="Email date">{message.date}</Field>
          <Field label="Analyzed at">{formatDate(analysis.analyzed_at)}</Field>
          <Field label="Message-ID">{message.message_id}</Field>
          <Field label="From"><ItemList items={message.from} /></Field>
          <Field label="To"><ItemList items={message.to} /></Field>
          <Field label="Cc"><ItemList items={message.cc} /></Field>
          <Field label="Reply-To"><ItemList items={message.reply_to} /></Field>
          <Field label="Return-Path">{message.return_path}</Field>
        </dl>
        {analysis.body?.sanitized_text && (
          <details className="mt-4 rounded-md bg-slate-50 p-3">
            <summary className="cursor-pointer font-medium">View sanitized message body</summary>
            <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono text-xs">
              {analysis.body.sanitized_text}
            </pre>
          </details>
        )}
        {analysis.attachments?.length > 0 && (
          <div className="mt-4">
            <h4 className="mb-2 font-medium">Attachment metadata (not opened or executed)</h4>
            <ItemList
              items={analysis.attachments}
              renderItem={(item) => `${item.filename} · ${item.mime_type} · ${item.size} bytes · SHA-256 ${item.sha256}`}
            />
          </div>
        )}
      </Section>

      <Section title="3. ML Classification">
        <dl className="grid gap-4 sm:grid-cols-3">
          <Field label="Normalized classification">
            {ml.prediction === 'PHISHING' ? 'MALICIOUS' : ml.prediction === 'LEGITIMATE' ? 'BENIGN' : '—'}
          </Field>
          <Field label="ML classification">{formatLabel(ml.prediction)}</Field>
          <Field label="Phishing probability">
            {typeof ml.probability === 'number' ? `${(ml.probability * 100).toFixed(1)}%` : '—'}
          </Field>
          <Field label="Model">{ml.model || modelInfo?.model}</Field>
          <Field label="Feature extraction">{modelInfo?.feature_extraction || 'TF-IDF'}</Field>
          <Field label="Model status">
            {modelInfo?.status || (ml.available ? 'Available for this analysis' : 'Unavailable')}
          </Field>
        </dl>
        {modelInfo?.test_metrics && (
          <div className="mt-4">
            <h4 className="mb-2 font-medium">Saved test-set evaluation metrics</h4>
            <dl className="grid gap-3 sm:grid-cols-4">
              <Metric label="Accuracy" value={modelInfo.test_metrics.accuracy} />
              <Metric label="Precision" value={modelInfo.test_metrics.precision} />
              <Metric label="Recall" value={modelInfo.test_metrics.recall} />
              <Metric label="F1 score" value={modelInfo.test_metrics.f1_score} />
            </dl>
            <p className="mt-2 text-xs text-slate-500">
              Values are read from the existing metrics.json test evaluation; they are not a production-performance guarantee.
              {modelInfo.trained_at ? ` Training timestamp: ${formatDate(modelInfo.trained_at)}.` : ''}
            </p>
          </div>
        )}
        {modelInfoError && <p role="alert" className="mt-3 text-sm text-amber-800">{modelInfoError}</p>}
        {ml.message && <p className="mt-3 text-sm text-slate-600">{ml.message}</p>}
        <p className="mt-3 text-xs text-slate-500">
          The classifier is one component of a hybrid forensic pipeline; it does not perform the full analysis by itself.
        </p>
      </Section>

      <Section title="4. Threat Detection / Rule Indicators">
        <div className="mb-4 flex flex-wrap gap-4 rounded-md bg-slate-50 p-3">
          <p><span className="font-medium">Rule score:</span> {threat.rule_score ?? '—'} / 100</p>
          <p><span className="font-medium">Indicators:</span> {threat.indicators?.length || 0}</p>
        </div>
        <p className="mb-3">{threat.summary || 'No rule-detection summary was returned.'}</p>
        <ItemList
          items={threat.indicators}
          renderItem={(item) => (
            <article className="rounded-md border border-slate-200 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="font-semibold">{item.title}</h4>
                <span className="rounded bg-slate-100 px-2 py-1 text-xs font-semibold uppercase">{item.severity}</span>
              </div>
              <p className="mt-1">{item.description}</p>
              <p className="mt-2 break-all rounded bg-slate-50 p-2 font-mono text-xs">Evidence: {item.evidence}</p>
            </article>
          )}
        />
      </Section>

      <Section title="5. Extracted Indicators of Compromise">
        <p className="mb-4 rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900">
          Observed evidence extracted from this message. URLs are not visited or scanned; passive/inferred intelligence is shown separately below.
        </p>
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <h4 className="mb-2 font-medium">URLs</h4>
            <ItemList items={analysis.urls} renderItem={(item) => (
              <div className="rounded bg-slate-50 p-2">
                <p className="font-mono">{item.url}</p>
                <p className="text-xs text-slate-500">Host: {item.hostname || 'not parsed'} · Domain: {item.domain || 'not parsed'}</p>
              </div>
            )} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">Observed domains</h4>
            <ItemList items={domains} renderItem={(item) => (
              <div className="rounded bg-slate-50 p-2">
                <span className="font-mono">{item.domain}</span>
                <span className="ml-2 text-xs text-slate-500">Source: {item.source}</span>
                {(item.is_punycode || item.is_ip_literal) && (
                  <span className="block text-xs font-medium text-amber-800">
                    {item.is_punycode ? 'Punycode domain ' : ''}{item.is_ip_literal ? 'IP-literal domain' : ''}
                  </span>
                )}
              </div>
            )} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">Observed IP addresses</h4>
            <ItemList items={headerInfo.ips} renderItem={(item) => (
              <div className="rounded bg-slate-50 p-2">
                <span className="font-mono">{item.ip}</span> · {item.version} · {item.scope}
                <span className="block text-xs text-slate-500">Source: {item.sources?.join(', ') || '—'}</span>
              </div>
            )} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">Potentially suspicious domain traits</h4>
            <ItemList items={suspiciousDomains} renderItem={(item) => `${item.domain} (${item.is_punycode ? 'punycode' : 'IP literal'})`} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">IP-literal URLs</h4>
            <ItemList items={ipLiteralUrls} renderItem={(item) => item.url} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">Sender / Reply-To domains</h4>
            <p className="font-medium">Sender</p>
            <ItemList items={senderDomains(domains, 'message.from')} renderItem={(item) => item.domain} />
            <p className="mt-2 font-medium">Reply-To</p>
            <ItemList items={senderDomains(domains, 'message.reply_to')} renderItem={(item) => item.domain} />
          </div>
          <div className="md:col-span-2">
            <h4 className="mb-2 font-medium">Suspicious header evidence</h4>
            <ItemList items={headerInfo.anomalies} renderItem={(item) => (
              <div className="rounded border border-amber-200 bg-amber-50 p-2">
                <p className="font-medium">{item.title}</p>
                <p>{item.description}</p>
                <p className="mt-1 break-all font-mono text-xs">Evidence: {item.evidence}</p>
              </div>
            )} />
          </div>
        </div>
      </Section>

      <Section title="6. Header Intelligence">
        <p className="mb-3 text-xs text-slate-500">
          Header values and relay hops are observations from the submitted message, not independently verified sender identity.
        </p>
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <h4 className="mb-2 font-medium">Authentication-Results</h4>
            <ItemList items={headers.authentication_results} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">Received-SPF</h4>
            <ItemList items={headers.received_spf} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">DKIM-Signature</h4>
            <ItemList items={headers.dkim_signature} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">DMARC-related</h4>
            <ItemList items={headers.dmarc} />
          </div>
        </div>
        <h4 className="mb-2 mt-4 font-medium">Received relay chain</h4>
        <ItemList items={headerInfo.received_chain} renderItem={(hop) => (
          <details className="rounded-md border border-slate-200 p-3">
            <summary className="cursor-pointer">Hop {hop.hop}: {hop.from_host || 'unknown'} → {hop.by_host || 'unknown'}</summary>
            <p className="mt-2 break-all text-xs">Protocol: {hop.with_protocol || '—'} · Timestamp: {hop.timestamp || '—'} · IPs: {hop.ips?.join(', ') || '—'}</p>
            <pre className="mt-2 whitespace-pre-wrap break-words text-xs">{hop.raw}</pre>
          </details>
        )} />
        <details className="mt-4 rounded-md border border-slate-200 p-3">
          <summary className="cursor-pointer font-medium">View all preserved raw headers</summary>
          <div className="mt-3 space-y-3">
            {Object.entries(headers.raw || {}).length ? Object.entries(headers.raw).map(([name, values]) => (
              <div key={name}>
                <h5 className="font-medium">{name}</h5>
                <ItemList items={values} />
              </div>
            )) : <EmptyValue />}
          </div>
        </details>
      </Section>

      <Section title="7. Infrastructure Intelligence">
        <p className="mb-3 text-xs text-slate-500">
          Passive provider enrichment/inference for observed infrastructure; it does not actively scan URLs.
        </p>
        <p className="mb-3">
          {analysis.infrastructure_intelligence?.enabled
            ? analysis.infrastructure_intelligence.message || `Provider: ${analysis.infrastructure_intelligence.provider || '—'}`
            : 'Passive enrichment is disabled for this analysis.'}
        </p>
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <h4 className="mb-2 font-medium">IP intelligence</h4>
            <ItemList items={analysis.infrastructure_intelligence?.ip_intelligence} renderItem={(item) => (
              <div className="rounded bg-slate-50 p-2">
                <p className="font-mono">{item.ip}</p>
                <p>{item.organization || 'Organization unavailable'} · ASN {item.asn || '—'} · {item.status}</p>
                <p className="text-xs text-slate-500">{[item.city, item.region, item.country].filter(Boolean).join(', ') || item.message || 'No location metadata'}</p>
              </div>
            )} />
          </div>
          <div>
            <h4 className="mb-2 font-medium">Domain intelligence</h4>
            <ItemList items={analysis.infrastructure_intelligence?.domain_intelligence} renderItem={(item) => (
              <div className="rounded bg-slate-50 p-2">
                <p className="font-mono">{item.domain}</p>
                <p>Registrar: {item.registrar || 'unavailable'} · {item.status}</p>
                <p className="text-xs text-slate-500">{item.message || ''}</p>
              </div>
            )} />
          </div>
        </div>
      </Section>

      <Section title="8. Probable Origin">
        <p className="mb-3 text-xs text-slate-500">
          An estimate about observed mail infrastructure, not an attacker&apos;s physical location.
        </p>
        {analysis.probable_origin?.available ? (
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Confidence">{analysis.probable_origin.confidence}</Field>
            <Field label="Source IP">{analysis.probable_origin.source_ip}</Field>
            <Field label="Country">{[analysis.probable_origin.country, analysis.probable_origin.country_code].filter(Boolean).join(' · ')}</Field>
            <Field label="Region / City">{[analysis.probable_origin.region, analysis.probable_origin.city].filter(Boolean).join(' / ')}</Field>
            <Field label="ASN / Organization">{[analysis.probable_origin.asn, analysis.probable_origin.organization].filter(Boolean).join(' / ')}</Field>
            <Field label="ISP">{analysis.probable_origin.isp}</Field>
            <Field label="Reason" className="sm:col-span-2">{analysis.probable_origin.reason}</Field>
          </dl>
        ) : <p>{analysis.probable_origin?.reason || 'No probable-origin result was returned.'}</p>}
      </Section>

      <Section title="9. Campaign Correlation">
        {analysis.campaign_correlation?.matched ? (
          <>
            <dl className="grid gap-4 sm:grid-cols-3">
              <Field label="Matched">Yes</Field>
              <Field label="Similarity">{analysis.campaign_correlation.similarity_score}%</Field>
              <Field label="Confidence">{analysis.campaign_correlation.confidence}</Field>
              <Field label="Related analyses">{analysis.campaign_correlation.related_analysis_count}</Field>
            </dl>
            <h4 className="mb-2 mt-4 font-medium">Observed correlation signals</h4>
            <ItemList items={analysis.campaign_correlation.signals} />
          </>
        ) : <p>{analysis.campaign_correlation?.message || 'No related campaign match was returned.'}</p>}
        <p className="mt-3 text-xs text-slate-500">Correlation indicates similarity with stored analyses, not common ownership.</p>
      </Section>

      <Section title="10. Report / Export">
        <p className="text-slate-600">Download the PDF report generated from this stored analysis result.</p>
        <button
          type="button"
          onClick={handleDownloadReport}
          disabled={reportLoading || !analysis.analysis_id}
          className="mt-4 rounded-md bg-slate-800 px-4 py-2 text-sm font-medium text-white hover:bg-slate-900 disabled:cursor-not-allowed disabled:bg-slate-400"
        >
          {reportLoading ? 'Generating…' : 'Download PDF report'}
        </button>
        {reportError && (
          <p role="alert" className="mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {reportError} <Link className="underline" to="/login">Sign in</Link> if report access requires a token.
          </p>
        )}
      </Section>
    </div>
  )
}
