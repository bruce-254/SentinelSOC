import React, { useEffect, useState } from "react";
import { api, timeAgo } from "../api";
import { Card, Sev, Empty, Err } from "../ui";

export default function Events() {
  const [data, setData] = useState(null);
  const [meta, setMeta] = useState({ event_types: [], source_log_types: [], severities: [] });
  const [f, setF] = useState({ q: "", src_ip: "", username: "", severity: "", event_type: "", source_log_type: "" });
  const [page, setPage] = useState(1);
  const [error, setError] = useState(null);

  useEffect(() => { api("/events/meta").then(setMeta).catch(() => {}); }, []);

  function load(p = 1) {
    setPage(p);
    setError(null);
    api("/events/search", { params: { ...f, page: p, page_size: 30 } })
      .then(setData)
      .catch((e) => setError(e.message));
  }
  useEffect(() => { load(1); /* eslint-disable-next-line */ }, []);
  useEffect(() => { load(page); /* eslint-disable-next-line */ }, [page]);

  function submit(e) { e.preventDefault(); load(1); }

  const pages = data ? Math.max(1, data.pages) : 1;

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Event Explorer</div>
          <div className="subtitle">Normalized security events — {data ? data.total.toLocaleString() : "…"} results</div>
        </div>
      </div>
      <Err e={error} />
      <form className="filters" onSubmit={submit}>
        <div className="field"><label>Search</label><input value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} placeholder="message / ip / user" /></div>
        <div className="field"><label>Source IP</label><input value={f.src_ip} onChange={(e) => setF({ ...f, src_ip: e.target.value })} /></div>
        <div className="field"><label>Username</label><input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></div>
        <div className="field"><label>Severity</label>
          <select value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>
            <option value="">All</option>
            {meta.severities.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <div className="field"><label>Event type</label>
          <select value={f.event_type} onChange={(e) => setF({ ...f, event_type: e.target.value })}>
            <option value="">All</option>
            {meta.event_types.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <div className="field"><label>Source</label>
          <select value={f.source_log_type} onChange={(e) => setF({ ...f, source_log_type: e.target.value })}>
            <option value="">All</option>
            {meta.source_log_types.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <button className="btn primary">Search</button>
      </form>

      <Card>
        {!data ? <Empty text="Loading…" /> : data.items.length === 0 ? <Empty text="No events match your filters" /> : (
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Type</th><th>Severity</th><th>Source</th><th>Dest</th>
                <th>User</th><th>Device</th><th>Message</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{timeAgo(e.timestamp)}</td>
                  <td><span className="mono">{e.event_type}</span></td>
                  <td><Sev s={e.severity} /></td>
                  <td className="mono">{e.src_ip || "—"}</td>
                  <td className="mono">{e.dst_ip || e.destination || "—"}</td>
                  <td className="mono">{e.username || "—"}</td>
                  <td className="mono">{e.device || "—"}</td>
                  <td style={{ maxWidth: 260 }}><span className="muted">{e.message}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && data.total > 30 && (
          <div className="btn-row">
            <button className="btn small" disabled={page <= 1} onClick={() => setPage(page - 1)}>Prev</button>
            <span className="muted">Page {page} of {pages}</span>
            <button className="btn small" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        )}
      </Card>
    </div>
  );
}
