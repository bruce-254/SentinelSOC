import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api, fmt } from "../api";
import { Card, Sev, Status, Err, Ok } from "../ui";

export default function AlertDetail() {
  const { id } = useParams();
  const [a, setA] = useState(null);
  const [error, setError] = useState(null);
  const [ok, setOk] = useState(null);
  const [note, setNote] = useState("");

  function load() {
    api(`/alerts/${id}`).then(setA).catch((e) => setError(e.message));
  }
  useEffect(load, [id]);

  async function setStatus(status) {
    setError(null); setOk(null);
    try {
      await api(`/alerts/${id}`, { method: "PATCH", body: { status } });
      setOk(`Status set to ${status}`);
      load();
    } catch (e) { setError(e.message); }
  }

  async function saveNote() {
    if (!note.trim()) return;
    try {
      await api(`/alerts/${id}`, { method: "PATCH", body: { status: a.status, note } });
      setNote(""); setOk("Note recorded in audit log");
    } catch (e) { setError(e.message); }
  }

  if (error) return <Err e={error} />;
  if (!a) return <div className="empty">Loading…</div>;

  const evidence = a.evidence?.[0] || {};
  const factors = a.risk_factors || [];

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title"><Link to="/alerts">←</Link> {a.title}</div>
          <div className="subtitle">Alert #{a.id} · {fmt(a.created_at)}</div>
        </div>
        <div className="toolbar">
          {["new", "acknowledged", "investigating", "resolved", "false_positive"].map((s) => (
            <button key={s} className={"btn small" + (a.status === s ? " primary" : "")} onClick={() => setStatus(s)}>
              {s === "false_positive" ? "False positive" : s}
            </button>
          ))}
        </div>
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      <div className="grid cols-2">
        <Card title="Overview">
          <table>
            <tbody>
              <tr><td>Severity</td><td><Sev s={a.severity} /></td></tr>
              <tr><td>Risk score</td><td className="mono"><b>{a.risk_score}</b> / 100</td></tr>
              <tr><td>Status</td><td><Status s={a.status} /></td></tr>
              <tr><td>Source IP</td><td className="mono">{a.src_ip || "—"}</td></tr>
              <tr><td>Username</td><td className="mono">{a.username || "—"}</td></tr>
              <tr><td>Asset</td><td>{a.asset_name || "—"}</td></tr>
              <tr><td>Event type</td><td className="mono">{a.event_type || "—"}</td></tr>
              <tr><td>Rule ID</td><td className="mono">{a.rule_id || "—"}</td></tr>
            </tbody>
          </table>
        </Card>

        <Card title="Evidence">
          <div className="timeline">
            <div className="tl-item">
              <div className="t">Event</div>
              <div className="b">Rule: <b>{evidence.rule}</b></div>
              <div className="b mono muted">{fmt(evidence.timestamp)}</div>
              <div className="b">Source: <span className="mono">{evidence.src_ip || "—"}</span></div>
              <div className="b">User: <span className="mono">{evidence.username || "—"}</span></div>
              <div className="b muted">Volume: {evidence.volume}</div>
              {evidence.message && <div className="b mono muted" style={{ marginTop: 6 }}>“{evidence.message}”</div>}
            </div>
          </div>
          <div className="field" style={{ marginTop: 8 }}>
            <label>Analyst note (audited)</label>
            <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a triage note…" />
          </div>
          <button className="btn small" onClick={saveNote}>Save note</button>
        </Card>
      </div>

      <div style={{ height: 16 }} />

      <Card title="Why this risk score? (explainable risk)">
        {factors.length === 0 ? <div className="muted">No risk factors recorded.</div> : (
          <div>
            {factors.map((f, i) => (
              <div className="factor-row" key={i}>
                <div className="fname">{f.factor}</div>
                <div className="factor-bar"><div style={{ width: `${Math.min(100, f.contribution / 40 * 100)}%` }} /></div>
                <div className="fval">+{f.contribution}</div>
                <div className="muted" style={{ flex: 1 }}>{f.explanation}</div>
              </div>
            ))}
            <div style={{ marginTop: 10 }}>Total risk score: <b>{a.risk_score}</b> / 100</div>
          </div>
        )}
      </Card>
    </div>
  );
}
