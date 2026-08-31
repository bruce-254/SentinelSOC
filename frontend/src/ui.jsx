import React from "react";
import { timeAgo } from "./api";

export function Sev({ s }) {
  return <span className={`pill sev-${s || "info"}`}>{s || "info"}</span>;
}

export function Status({ s, kind = "alert" }) {
  const cls = `st-${(s || "").toLowerCase().replace(/\s+/g, "_")}`;
  return <span className={`pill ${cls}`}>{s}</span>;
}

export function Err({ e }) {
  if (!e) return null;
  return <div className="error-banner">{String(e)}</div>;
}

export function Ok({ msg }) {
  if (!msg) return null;
  return <div className="success-banner">{msg}</div>;
}

export function Time({ iso }) {
  return <span className="mono muted">{timeAgo(iso)}</span>;
}

export function Card({ title, children, className = "" }) {
  return (
    <div className={`card ${className}`}>
      {title && <h3>{title}</h3>}
      {children}
    </div>
  );
}

export function Stat({ label, value, sub, color }) {
  return (
    <Card>
      <div className="stat">
        <div className="label">{label}</div>
        <div className="value" style={color ? { color } : undefined}>{value}</div>
        {sub && <div className="sub">{sub}</div>}
      </div>
    </Card>
  );
}

export function Empty({ text }) {
  return <div className="empty">{text || "No data"}</div>;
}
