import React, { useState } from "react";
import { api } from "../api";
import { Card, Err } from "../ui";

export default function Reports() {
  const [from, setFrom] = useState(new Date(Date.now() - 86400000).toISOString().slice(0, 16));
  const [to, setTo] = useState(new Date().toISOString().slice(0, 16));
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function generate() {
    setError(null); setBusy(true); setReport(null);
    try {
      const r = await api("/reports/generate", {
        method: "POST",
        body: { report_type: "summary", time_from: new Date(from).toISOString(), time_to: new Date(to).toISOString() },
      });
      setReport(r);
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Reports</div>
          <div className="subtitle">Operational summary reports generated from live data</div>
        </div>
      </div>
      <Err e={error} />

      <div className="grid cols-2">
        <Card title="Generate report">
          <div className="field"><label>From</label><input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} /></div>
          <div className="field"><label>To</label><input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} /></div>
          <button className="btn primary" onClick={generate} disabled={busy}>{busy ? "Generating…" : "Generate summary report"}</button>
        </Card>

        <Card title="Report output">
          {!report ? <div className="muted">Run a report to see output here.</div> : (
            <div>
              <div className="muted">Generated {new Date(report.generated_at).toLocaleString()}</div>
              <table style={{ marginTop: 8 }}>
                <tbody>
                  <tr><td>Events</td><td className="mono">{report.summary.events_total}</td></tr>
                  <tr><td>Alerts</td><td className="mono">{report.summary.alerts_total}</td></tr>
                  <tr><td>Critical / High</td><td className="mono">{report.summary.critical_alerts} / {report.summary.high_alerts}</td></tr>
                  <tr><td>Failed logins</td><td className="mono">{report.summary.failed_logins}</td></tr>
                  <tr><td>Open incidents</td><td className="mono">{report.summary.open_incidents}</td></tr>
                </tbody>
              </table>
              <h4 className="muted" style={{ margin: "14px 0 6px", fontSize: 11, textTransform: "uppercase" }}>Top source IPs</h4>
              {report.top_source_ips.map((t) => <div key={t.ip} className="mono">{t.ip}: {t.count}</div>)}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
