import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, timeAgo } from "../api";
import { Card, Sev, Empty, Err } from "../ui";

export default function Incidents() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ title: "", description: "", severity: "medium", alert_ids: "" });
  const [ok, setOk] = useState(null);

  function load() {
    api("/incidents").then(setItems).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); }, []);

  async function create(e) {
    e.preventDefault();
    setError(null); setOk(null);
    try {
      const alert_ids = form.alert_ids.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
      await api("/incidents", { method: "POST", body: { title: form.title, description: form.description, severity: form.severity, alert_ids } });
      setShow(false);
      setForm({ title: "", description: "", severity: "medium", alert_ids: "" });
      setOk("Incident created");
      load();
    } catch (e) { setError(e.message); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Incidents</div>
          <div className="subtitle">Open, investigating, contained, resolved and closed incidents</div>
        </div>
        <button className="btn primary" onClick={() => setShow(!show)}>{show ? "Cancel" : "+ New incident"}</button>
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      {show && (
        <Card>
          <form onSubmit={create}>
            <div className="field"><label>Title</label><input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required /></div>
            <div className="field"><label>Description</label><textarea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
            <div className="field"><label>Severity</label>
              <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                {["info", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div className="field"><label>Linked alert IDs (comma-separated, optional)</label><input value={form.alert_ids} onChange={(e) => setForm({ ...form, alert_ids: e.target.value })} placeholder="12, 34" /></div>
            <button className="btn primary" type="submit">Create incident</button>
          </form>
        </Card>
      )}

      <div style={{ height: 16 }} />

      <Card>
        {!items ? <Empty text="Loading…" /> : items.length === 0 ? <Empty text="No incidents yet" /> : (
          <table>
            <thead>
              <tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Alerts</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id} className="clickable">
                  <td className="mono">{i.id}</td>
                  <td><Link to={`/incidents/${i.id}`}>{i.title}</Link></td>
                  <td><Sev s={i.severity} /></td>
                  <td><span className={`pill st-${i.status}`}>{i.status}</span></td>
                  <td className="mono">{i.alert_ids?.length || 0}</td>
                  <td className="mono">{timeAgo(i.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
