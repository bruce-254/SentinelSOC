import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, timeAgo } from "../api";
import { Card, Sev, Empty, Err } from "../ui";

export default function Alerts() {
  const [data, setData] = useState(null);
  const [f, setF] = useState({ status: "", severity: "" });
  const [error, setError] = useState(null);

  function load() {
    setError(null);
    api("/alerts", { params: { ...f, limit: 200 } })
      .then(setData)
      .catch((e) => setError(e.message));
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [f]);

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Alert Queue</div>
          <div className="subtitle">Detections requiring attention — {data ? data.total.toLocaleString() : "…"}</div>
        </div>
        <div className="toolbar">
          <select value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })} style={{ width: 140 }}>
            <option value="">All status</option>
            {["new", "acknowledged", "investigating", "resolved", "false_positive"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })} style={{ width: 140 }}>
            <option value="">All severity</option>
            {["info", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
      </div>
      <Err e={error} />
      <Card>
        {!data ? <Empty text="Loading…" /> : data.items.length === 0 ? <Empty text="No alerts" /> : (
          <table>
            <thead>
              <tr>
                <th>Severity</th><th>Risk</th><th>Title</th><th>Status</th><th>Source</th>
                <th>User</th><th>Asset</th><th>Time</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id} className="clickable">
                  <td><Sev s={a.severity} /></td>
                  <td className="mono"><b>{a.risk_score}</b></td>
                  <td><Link to={`/alerts/${a.id}`}>{a.title}</Link></td>
                  <td><span className={`pill st-${a.status}`}>{a.status}</span></td>
                  <td className="mono">{a.src_ip || "—"}</td>
                  <td className="mono">{a.username || "—"}</td>
                  <td className="mono">{a.asset_name || "—"}</td>
                  <td className="mono">{timeAgo(a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
