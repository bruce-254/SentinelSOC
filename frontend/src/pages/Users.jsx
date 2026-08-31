import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Empty, Err, Ok } from "../ui";
import { useAuth } from "../auth";

const ROLES = ["admin", "analyst", "viewer"];

export default function Users() {
  const { user } = useAuth();
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [ok, setOk] = useState(null);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "analyst" });

  const isAdmin = user?.role === "admin";
  function load() { api("/users").then(setItems).catch((e) => setError(e.message)); }
  useEffect(() => { load(); }, []);

  async function create(e) {
    e.preventDefault();
    setError(null); setOk(null);
    try {
      await api("/users", { method: "POST", body: form });
      setForm({ username: "", email: "", password: "", role: "analyst" });
      setOk("User created");
      load();
    } catch (e) { setError(e.message); }
  }

  async function setRole(id, role) {
    try { await api(`/users/${id}`, { method: "PATCH", body: { role } }); load(); } catch (e) { setError(e.message); }
  }
  async function toggleActive(u) {
    try { await api(`/users/${u.id}`, { method: "PATCH", body: { is_active: !u.is_active } }); load(); } catch (e) { setError(e.message); }
  }

  if (!isAdmin) return <div className="empty">You do not have permission to manage users.</div>;

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Users &amp; Roles</div>
          <div className="subtitle">Role-based access control — admin, analyst, viewer</div>
        </div>
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      <Card>
        <h3>Create user</h3>
        <form onSubmit={create}>
          <div className="grid cols-4">
            <div className="field"><label>Username</label><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required /></div>
            <div className="field"><label>Email</label><input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></div>
            <div className="field"><label>Password</label><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={8} /></div>
            <div className="field"><label>Role</label>
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {ROLES.map((r) => <option key={r}>{r}</option>)}
              </select>
            </div>
          </div>
          <button className="btn primary" type="submit">Create user</button>
        </form>
      </Card>

      <div style={{ height: 16 }} />

      <Card>
        {!items ? <Empty text="Loading…" /> : (
          <table>
            <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Active</th><th>Last login</th><th>Actions</th></tr></thead>
            <tbody>
              {items.map((u) => (
                <tr key={u.id}>
                  <td className="mono"><b>{u.username}</b>{u.id === user.id && <span className="muted"> (you)</span>}</td>
                  <td>{u.email}</td>
                  <td>
                    <select value={u.role} onChange={(e) => setRole(u.id, e.target.value)} style={{ width: 120 }}>
                      {ROLES.map((r) => <option key={r}>{r}</option>)}
                    </select>
                  </td>
                  <td>{u.is_active ? <span className="pill st-resolved">active</span> : <span className="pill st-closed">disabled</span>}</td>
                  <td className="mono">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}</td>
                  <td><button className="btn small" onClick={() => toggleActive(u)} disabled={u.id === user.id}>{u.is_active ? "Disable" : "Enable"}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
