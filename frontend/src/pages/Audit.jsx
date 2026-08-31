import React, { useEffect, useState } from "react";
import { api, fmt } from "../api";
import { Card, Empty, Err } from "../ui";

export default function Audit() {
  const [items, setItems] = useState(null);
  const [action, setAction] = useState("");
  const [error, setError] = useState(null);

  function load() {
    api("/audit", { params: action ? { action, limit: 500 } : { limit: 500 } })
      .then(setItems).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); }, [action]);

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Audit Log</div>
          <div className="subtitle">Every analyst and administrator action, recorded</div>
        </div>
        <div className="toolbar">
          <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="Filter by action…" style={{ width: 220 }} />
        </div>
      </div>
      <Err e={error} />
      <Card>
        {!items ? <Empty text="Loading…" /> : items.length === 0 ? <Empty text="No audit entries" /> : (
          <table>
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>Details</th><th>IP</th></tr></thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{fmt(a.created_at)}</td>
                  <td className="mono">{a.username || "system"}</td>
                  <td><span className="pill sev-info">{a.action}</span></td>
                  <td className="mono">{a.resource || "—"} {a.resource_id ? `#${a.resource_id}` : ""}</td>
                  <td className="muted" style={{ maxWidth: 260 }}>{a.details ? JSON.stringify(a.details) : "—"}</td>
                  <td className="mono">{a.ip_address || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
