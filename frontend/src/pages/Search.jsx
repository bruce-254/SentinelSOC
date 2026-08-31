import React, { useEffect, useState } from "react";
import { api, timeAgo } from "../api";
import { Card, Sev, Empty, Err } from "../ui";

function nowIso(minAgo) {
  return new Date(Date.now() - minAgo * 60000).toISOString().slice(0, 16);
}

export default function Search() {
  const [results, setResults] = useState(null);
  const [meta, setMeta] = useState({ event_types: [], severities: [] });
  const [f, setF] = useState({
    q: "", src_ip: "", username: "", asset: "", severity: "", event_type: "",
    time_from: nowIso(1440), time_to: "",
  });
  const [error, setError] = useState(null);

  useEffect(() => { api("/events/meta").then(setMeta).catch(() => {}); }, []);

  function run(e) {
    if (e) e.preventDefault();
    setError(null);
    const params = {
      q: f.q, src_ip: f.src_ip, username: f.username, severity: f.severity,
      event_type: f.event_type, page_size: 100,
    };
    if (f.time_from) params.time_from = new Date(f.time_from).toISOString();
    if (f.time_to) params.time_to = new Date(f.time_to).toISOString();
    if (f.asset) params.q = `${params.q || ""} ${f.asset}`.trim();
    api("/events/search", { params })
      .then(setResults)
      .catch((e) => setError(e.message));
  }
  useEffect(() => { run(); /* eslint-disable-next-line */ }, []);

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Event Search</div>
          <div className="subtitle">Full-text and filtered search across normalized events</div>
        </div>
      </div>
      <Err e={error} />
      <form className="filters" onSubmit={run}>
        <div className="field"><label>Query</label><input value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} placeholder="message text / host / user" /></div>
        <div className="field"><label>IP</label><input value={f.src_ip} onChange={(e) => setF({ ...f, src_ip: e.target.value })} placeholder="source IP" /></div>
        <div className="field"><label>Username</label><input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></div>
        <div className="field"><label>From</label><input type="datetime-local" value={f.time_from} onChange={(e) => setF({ ...f, time_from: e.target.value })} /></div>
        <div className="field"><label>To</label><input type="datetime-local" value={f.time_to} onChange={(e) => setF({ ...f, time_to: e.target.value })} /></div>
        <div className="field"><label>Severity</label>
          <select value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>
            <option value="">All</option>{meta.severities.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <div className="field"><label>Event type</label>
          <select value={f.event_type} onChange={(e) => setF({ ...f, event_type: e.target.value })}>
            <option value="">All</option>{meta.event_types.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <button className="btn primary">Run search</button>
      </form>

      <Card>
        {!results ? <Empty text="Searching…" /> : results.items.length === 0 ? <Empty text="No events matched your query" /> : (
          <table>
            <thead>
              <tr><th>Time</th><th>Type</th><th>Severity</th><th>Src IP</th><th>User</th><th>Device</th><th>Message</th></tr>
            </thead>
            <tbody>
              {results.items.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{timeAgo(e.timestamp)}</td>
                  <td><span className="mono">{e.event_type}</span></td>
                  <td><Sev s={e.severity} /></td>
                  <td className="mono">{e.src_ip || "—"}</td>
                  <td className="mono">{e.username || "—"}</td>
                  <td className="mono">{e.device || "—"}</td>
                  <td style={{ maxWidth: 300 }}><span className="muted">{e.message}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
