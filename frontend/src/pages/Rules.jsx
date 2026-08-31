import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Sev, Empty, Err, Ok } from "../ui";
import { useAuth } from "../auth";

const BLANK = {
  name: "", description: "", rule_type: "single_event",
  scope: "{}", conditions: "{}", time_window_seconds: 300, threshold: 5,
  group_by: "src_ip", enabled: true, priority: 50, severity: "medium",
  alert_title: "", risk_weight: 1.0,
};

export default function Rules() {
  const { user } = useAuth();
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [ok, setOk] = useState(null);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(BLANK);

  function load() {
    api("/rules").then(setItems).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); }, []);

  function startCreate() {
    setEditing(null); setForm(BLANK);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  function startEdit(r) {
    setEditing(r.id);
    setForm({
      ...r, scope: JSON.stringify(r.scope), conditions: JSON.stringify(r.conditions),
      time_window_seconds: r.time_window_seconds ?? 300, threshold: r.threshold ?? 5,
      group_by: r.group_by || "src_ip", alert_title: r.alert_title || "",
    });
  }

  async function toggle(r) {
    try {
      await api(`/rules/${r.id}/${r.enabled ? "disable" : "enable"}`, { method: "POST" });
      load();
    } catch (e) { setError(e.message); }
  }

  async function save(e) {
    e.preventDefault();
    setError(null); setOk(null);
    let scope, conditions;
    try { scope = JSON.parse(form.scope || "{}"); } catch { return setError("scope must be valid JSON"); }
    try { conditions = JSON.parse(form.conditions || "{}"); } catch { return setError("conditions must be valid JSON"); }
    const body = {
      name: form.name, description: form.description, rule_type: form.rule_type,
      scope, conditions, enabled: form.enabled, priority: Number(form.priority),
      severity: form.severity, alert_title: form.alert_title, risk_weight: Number(form.risk_weight),
    };
    if (form.rule_type === "aggregate") {
      body.time_window_seconds = Number(form.time_window_seconds);
      body.threshold = Number(form.threshold);
      body.group_by = form.group_by;
    }
    try {
      if (editing) await api(`/rules/${editing}`, { method: "PATCH", body });
      else await api("/rules", { method: "POST", body });
      setOk(editing ? "Rule updated" : "Rule created");
      setEditing(null); setForm(BLANK);
      load();
    } catch (e) { setError(e.message); }
  }

  const isAdmin = user?.role === "admin";

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Detection Rules</div>
          <div className="subtitle">Configurable, database-backed detection rules ({items ? items.length : "…"} total)</div>
        </div>
        {isAdmin && <button className="btn primary" onClick={startCreate}>+ New rule</button>}
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      {isAdmin && (
        <Card>
          <h3>{editing ? "Edit rule" : "Create rule"}</h3>
          <form onSubmit={save}>
            <div className="grid cols-2">
              <div className="field"><label>Name</label><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
              <div className="field"><label>Alert title template</label><input value={form.alert_title} onChange={(e) => setForm({ ...form, alert_title: e.target.value })} placeholder="{src_ip} {username}…" /></div>
              <div className="field"><label>Description</label><textarea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
              <div className="field"><label>Rule type</label>
                <select value={form.rule_type} onChange={(e) => setForm({ ...form, rule_type: e.target.value })}>
                  <option value="single_event">Single event</option>
                  <option value="aggregate">Aggregate (threshold)</option>
                </select>
              </div>
              <div className="field"><label>Scope (JSON) — e.g. {"{"}"event_types": ["authentication_failure"]{"}"}</label><input value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} className="mono" /></div>
              <div className="field"><label>Conditions (JSON) — e.g. {"{"}"username": {"{"}"eq": "root"{"}"}{"}"}</label><input value={form.conditions} onChange={(e) => setForm({ ...form, conditions: e.target.value })} className="mono" /></div>
              {form.rule_type === "aggregate" && (
                <>
                  <div className="field"><label>Time window (seconds)</label><input type="number" value={form.time_window_seconds} onChange={(e) => setForm({ ...form, time_window_seconds: e.target.value })} /></div>
                  <div className="field"><label>Threshold</label><input type="number" value={form.threshold} onChange={(e) => setForm({ ...form, threshold: e.target.value })} /></div>
                  <div className="field"><label>Group by</label>
                    <select value={form.group_by} onChange={(e) => setForm({ ...form, group_by: e.target.value })}>
                      {["src_ip", "dst_ip", "username", "device", "dst_port"].map((g) => <option key={g}>{g}</option>)}
                    </select>
                  </div>
                </>
              )}
              <div className="field"><label>Severity</label>
                <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                  {["info", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
                </select>
              </div>
              <div className="field"><label>Priority (1–100)</label><input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })} /></div>
              <div className="field"><label>Risk weight (0–10)</label><input type="number" step="0.1" value={form.risk_weight} onChange={(e) => setForm({ ...form, risk_weight: e.target.value })} /></div>
              <div className="field"><label>Enabled</label>
                <select value={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.value === "true" })}>
                  <option value="true">Yes</option><option value="false">No</option>
                </select>
              </div>
            </div>
            <div className="btn-row">
              <button className="btn primary" type="submit">{editing ? "Save changes" : "Create rule"}</button>
              <button className="btn" type="button" onClick={() => { setEditing(null); setForm(BLANK); }}>Cancel</button>
            </div>
          </form>
        </Card>
      )}

      <div style={{ height: 16 }} />

      <Card>
        {!items ? <Empty text="Loading…" /> : items.length === 0 ? <Empty text="No rules" /> : (
          <table>
            <thead>
              <tr><th>Priority</th><th>Name</th><th>Type</th><th>Severity</th><th>Status</th><th>Window</th><th>Threshold</th><th>Group</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.priority}</td>
                  <td><b>{r.name}</b><div className="muted" style={{ fontSize: 11 }}>{r.description}</div></td>
                  <td className="mono">{r.rule_type}</td>
                  <td><Sev s={r.severity} /></td>
                  <td>{r.enabled ? <span className="pill st-resolved">enabled</span> : <span className="pill st-closed">disabled</span>}</td>
                  <td className="mono">{r.time_window_seconds ? `${r.time_window_seconds}s` : "—"}</td>
                  <td className="mono">{r.threshold ?? "—"}</td>
                  <td className="mono">{r.group_by || "—"}</td>
                  <td>
                    {isAdmin && (
                      <div className="toolbar">
                        <button className="btn small" onClick={() => startEdit(r)}>Edit</button>
                        <button className="btn small" onClick={() => toggle(r)}>{r.enabled ? "Disable" : "Enable"}</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
