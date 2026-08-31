import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Empty, Err, Ok } from "../ui";

export default function ThreatIntel() {
  const [items, setItems] = useState(null);
  const [providers, setProviders] = useState(null);
  const [error, setError] = useState(null);
  const [ok, setOk] = useState(null);

  function load() {
    api("/threatintel").then(setItems).catch((e) => setError(e.message));
    fetch("/api/threatintel/providers").then((r) => r.json()).then(setProviders).catch(() => {});
  }
  useEffect(() => { load(); }, []);

  async function sync() {
    setError(null); setOk(null);
    try {
      const r = await api("/threatintel/sync", { method: "POST" });
      setOk(`Sync complete: ${r.synced} indicators from ${r.providers.length} provider(s)`);
      load();
    } catch (e) { setError(e.message); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Threat Intelligence</div>
          <div className="subtitle">Extensible provider interface · indicators are real, never fabricated</div>
        </div>
        <button className="btn primary" onClick={sync}>Sync providers</button>
      </div>
      <Err e={error} />
      <Ok msg={ok} />

      <Card title="Configured providers" className="" >
        {!providers ? <div className="muted">Loading providers…</div> : providers.length === 0 ? (
          <div className="muted">No providers registered.</div>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Requires API key</th><th>Status</th></tr></thead>
            <tbody>
              {providers.map((p) => (
                <tr key={p.name}>
                  <td className="mono">{p.name}</td>
                  <td>{p.requires_api_key ? "yes" : "no"}</td>
                  <td><span className="pill st-resolved">{p.enabled ? "active" : "disabled"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <div style={{ height: 16 }} />

      <Card title="Stored indicators">
        {!items ? <Empty text="Loading…" /> : items.length === 0 ? (
          <Empty text="No indicators stored. The bundled development provider returns an empty dataset by design — add a real provider to populate this." />
        ) : (
          <table>
            <thead><tr><th>Type</th><th>Value</th><th>Provider</th><th>Confidence</th><th>Tags</th></tr></thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id}>
                  <td className="mono">{i.indicator_type}</td>
                  <td className="mono">{i.value}</td>
                  <td className="mono">{i.provider}</td>
                  <td>{i.confidence}</td>
                  <td>{(i.tags || []).map((t) => <span key={t} className="pill sev-info" style={{ marginRight: 4 }}>{t}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
