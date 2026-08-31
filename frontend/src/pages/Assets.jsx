import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Sev, Empty, Err, Ok } from "../ui";
import { useAuth } from "../auth";

export default function Assets() {
  const { user } = useAuth();
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [ok, setOk] = useState(null);
  const [form, setForm] = useState({ name: "", ip_address: "", hostname: "", os: "", criticality: "medium", tags: "", notes: "" });

  const canEdit = user?.role !== "viewer";
  function load() { api("/assets").then(setItems).catch((e) => setError(e.message)); }
  useEffect(() => { load(); }, []);

  async function save(e) {
    e.preventDefault();
    setError(null); setOk(null);
    const body = { ...form, tags: form.tags ? form.tags.split(",").map((t) => t.trim()).filter(Boolean) : [] };
    try {
      await api("/assets", { method: "POST", body });
      setOk("Asset added");
      setForm({ name: "", ip_address: "", hostname: "", os: "", criticality: "medium", tags: "", notes: "" });
      load();
    } catch (e) { setError(e.message); }
  }

  async function remove(id) {
    if (!confirm("Delete this asset?")) return;
    try { await api(`/assets/${id}`, { method: "DELETE" }); load(); } catch (e) { setError(e.message); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Asset Inventory</div>
          <div className="subtitle">{items ? items.length : "…"} assets · used for enrichment and risk scoring</div>
        </div>
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      {canEdit && (
        <Card>
          <h3>Add asset</h3>
          <form onSubmit={save}>
            <div className="grid cols-4">
              <div className="field"><label>Name</label><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
              <div className="field"><label>IP</label><input value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} required /></div>
              <div className="field"><label>Hostname</label><input value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} /></div>
              <div className="field"><label>OS</label><input value={form.os} onChange={(e) => setForm({ ...form, os: e.target.value })} /></div>
              <div className="field"><label>Criticality</label>
                <select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
                  {["info", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
                </select>
              </div>
              <div className="field"><label>Tags (comma)</label><input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} /></div>
              <div className="field"><label>Notes</label><input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></div>
              <div className="field"><label>&nbsp;</label><button className="btn primary" type="submit">Add asset</button></div>
            </div>
          </form>
        </Card>
      )}

      <div style={{ height: 16 }} />

      <Card>
        {!items ? <Empty text="Loading…" /> : items.length === 0 ? <Empty text="No assets" /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>IP</th><th>Hostname</th><th>OS</th><th>Criticality</th><th>Tags</th>{canEdit && <th></th>}</tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td><b>{a.name}</b></td>
                  <td className="mono">{a.ip_address}</td>
                  <td className="mono">{a.hostname || "—"}</td>
                  <td>{a.os || "—"}</td>
                  <td><Sev s={a.criticality} /></td>
                  <td>{(a.tags || []).map((t) => <span key={t} className="pill sev-info" style={{ marginRight: 4 }}>{t}</span>)}</td>
                  {canEdit && <td><button className="btn small danger" onClick={() => remove(a.id)}>Delete</button></td>}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
