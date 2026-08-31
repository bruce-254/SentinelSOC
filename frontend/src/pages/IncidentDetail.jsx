import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api, fmt } from "../api";
import { Card, Sev, Empty, Err, Ok } from "../ui";

export default function IncidentDetail() {
  const { id } = useParams();
  const [inc, setInc] = useState(null);
  const [error, setError] = useState(null);
  const [ok, setOk] = useState(null);
  const [note, setNote] = useState("");

  function load() { api(`/incidents/${id}`).then(setInc).catch((e) => setError(e.message)); }
  useEffect(load, [id]);

  async function update(patch) {
    setError(null); setOk(null);
    try {
      await api(`/incidents/${id}`, { method: "PATCH", body: patch });
      setOk("Incident updated");
      load();
    } catch (e) { setError(e.message); }
  }

  async function addNote(e) {
    e.preventDefault();
    if (!note.trim()) return;
    try {
      await api(`/incidents/${id}/notes`, { method: "POST", body: { body: note } });
      setNote(""); load();
    } catch (e) { setError(e.message); }
  }

  if (error) return <Err e={error} />;
  if (!inc) return <div className="empty">Loading…</div>;

  const statuses = ["open", "investigating", "contained", "resolved", "closed"];

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title"><Link to="/incidents">←</Link> {inc.title}</div>
          <div className="subtitle">Incident #{inc.id} · created {fmt(inc.created_at)}</div>
        </div>
        <div className="toolbar">
          {statuses.map((s) => (
            <button key={s} className={"btn small" + (inc.status === s ? " primary" : "")} onClick={() => update({ status: s })}>{s}</button>
          ))}
        </div>
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      <div className="grid cols-2">
        <Card title="Details">
          <table>
            <tbody>
              <tr><td>Severity</td><td><Sev s={inc.severity} /></td></tr>
              <tr><td>Status</td><td><span className={`pill st-${inc.status}`}>{inc.status}</span></td></tr>
              <tr><td>Linked alerts</td><td className="mono">{(inc.alert_ids || []).join(", ") || "—"}</td></tr>
              <tr><td>Created</td><td className="mono">{fmt(inc.created_at)}</td></tr>
              <tr><td>Resolved</td><td className="mono">{inc.resolved_at ? fmt(inc.resolved_at) : "—"}</td></tr>
              {inc.description && <tr><td>Description</td><td>{inc.description}</td></tr>}
            </tbody>
          </table>
        </Card>

        <Card title="Analyst timeline">
          <form className="btn-row" onSubmit={addNote} style={{ marginBottom: 14 }}>
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note…" style={{ flex: 1 }} />
            <button className="btn small primary" type="submit">Add</button>
          </form>
          {inc.notes?.length === 0 ? <Empty text="No notes yet" /> : (
            <div className="timeline">
              {inc.notes?.map((n) => (
                <div className="tl-item" key={n.id}>
                  <div className="t">{fmt(n.created_at)} {n.status_change ? `→ ${n.status_change}` : ""}</div>
                  <div className="b">{n.body}</div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
