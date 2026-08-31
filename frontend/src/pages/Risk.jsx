import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Empty, Err } from "../ui";

const LEVEL_COLORS = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#22d3ee", info: "#8ba0c7" };

export default function Risk() {
  const [items, setItems] = useState(null);
  const [entityType, setEntityType] = useState("");
  const [error, setError] = useState(null);

  function load() {
    api("/risk", { params: entityType ? { entity_type: entityType } : {} })
      .then(setItems).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); }, [entityType]);

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">Risk Scoring</div>
          <div className="subtitle">Explainable entity risk — tap a row to see contributing factors and alerts</div>
        </div>
        <div className="toolbar">
          <select value={entityType} onChange={(e) => setEntityType(e.target.value)} style={{ width: 160 }}>
            <option value="">All entities</option>
            <option value="asset">Assets</option>
            <option value="ip">Source IPs</option>
            <option value="user">Users</option>
          </select>
        </div>
      </div>
      <Err e={error} />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {["critical", "high", "medium", "low"].map((lvl) => (
          <Card key={lvl}>
            <div className="stat">
              <div className="label">{lvl.toUpperCase()} risk</div>
              <div className="value" style={{ color: LEVEL_COLORS[lvl] }}>
                {(items || []).filter((s) => s.level === lvl).length}
              </div>
            </div>
          </Card>
        ))}
      </div>

      <Card>
        {!items ? <Empty text="Loading…" /> : items.length === 0 ? <Empty text="No risk scores yet — ingest events to generate them" /> : (
          <table>
            <thead><tr><th>Entity</th><th>Label</th><th>Score</th><th>Level</th><th>Updated</th></tr></thead>
            <tbody>
              {items.map((s) => (
                <Row key={`${s.entity_type}-${s.entity_id}`} s={s} />
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

function Row({ s }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="clickable" onClick={() => setOpen(!open)}>
        <td><b>{s.entity_type}</b></td>
        <td className="mono">{s.entity_label || s.entity_id}</td>
        <td className="mono"><b>{s.score}</b></td>
        <td><span className={`pill sev-${s.level}`} style={{ color: LEVEL_COLORS[s.level], border: `1px solid ${LEVEL_COLORS[s.level]}`, background: "transparent" }}>{s.level}</span></td>
        <td className="mono">{new Date(s.updated_at).toLocaleString()}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5} style={{ background: "var(--bg-2)" }}>
            <div style={{ padding: 8 }}>
              <h4 className="muted" style={{ margin: "0 0 8px", textTransform: "uppercase", fontSize: 11 }}>Contributing factors</h4>
              {s.factors.length === 0 ? <div className="muted">No factors recorded</div> : s.factors.map((f, i) => (
                <div className="factor-row" key={i}>
                  <div className="fname">{f.factor}</div>
                  <div className="factor-bar"><div style={{ width: `${Math.min(100, f.contribution / 40 * 100)}%` }} /></div>
                  <div className="fval">+{f.contribution}</div>
                  <div className="muted" style={{ flex: 1 }}>{f.explanation}</div>
                </div>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
