import React, { useEffect, useState } from "react";
import {
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  CartesianGrid, PieChart, Pie, Cell, Legend,
} from "recharts";
import { api } from "../api";
import { Card, Stat, Sev, Empty } from "../ui";

const SEV_COLORS = {
  critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#22d3ee", info: "#8ba0c7",
};

export default function Dashboard() {
  const [d, setD] = useState(null);
  const [error, setError] = useState(null);
  const [window, setWindow] = useState(60);

  useEffect(() => {
    api(`/dashboard?window_minutes=${window}`)
      .then(setD)
      .catch((e) => setError(e.message));
  }, [window]);

  if (error) return <div className="error-banner">{error}</div>;
  if (!d) return <div className="empty">Loading dashboard…</div>;

  const severityData = Object.entries(d.severity_distribution).map(([k, v]) => ({
    name: k, value: v, fill: SEV_COLORS[k] || "#8ba0c7",
  }));
  const incidentData = Object.entries(d.incident_status_distribution).map(([k, v]) => ({
    name: k.replace(/_/g, " "), value: v,
  }));
  const eventTypeData = Object.entries(d.event_types)
    .sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([k, v]) => ({ name: k, count: v }));

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-title">{d.org.name} — Overview</div>
          <div className="subtitle">Last {window} minutes &nbsp;·&nbsp; {d.events_total.toLocaleString()} total events</div>
        </div>
        <div className="toolbar">
          {[15, 60, 360, 1440].map((w) => (
            <button key={w} className={"btn small" + (window === w ? " primary" : "")}
              onClick={() => setWindow(w)}>
              {w < 60 ? `${w}m` : w === 60 ? "1h" : w === 360 ? "6h" : "24h"}
            </button>
          ))}
        </div>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="Events (total)" value={d.events_total.toLocaleString()} sub={`${d.events_per_minute}/min recent`} />
        <Stat label="Alerts" value={d.alerts_total.toLocaleString()} sub={`${d.critical_alerts} critical`} color={d.critical_alerts ? "#ef4444" : undefined} />
        <Stat label="Failed Logins" value={d.failed_logins} sub="last window" color={d.failed_logins ? "#f59e0b" : undefined} />
        <Stat label="Open Incidents" value={d.open_incidents} sub={`${d.active_rules} active rules`} />
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Card title="Events per minute">
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={d.event_rate_series}>
              <defs>
                <linearGradient id="gE" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.6} />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#223055" strokeDasharray="3 3" />
              <XAxis dataKey="t" tickFormatter={(t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} stroke="#8ba0c7" fontSize={10} />
              <YAxis stroke="#8ba0c7" fontSize={10} />
              <Tooltip contentStyle={{ background: "#131c33", border: "1px solid #223055", borderRadius: 8 }} labelFormatter={(t) => new Date(t).toLocaleString()} />
              <Area type="monotone" dataKey="value" stroke="#3b82f6" fill="url(#gE)" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Authentication trend">
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={d.auth_trend_series}>
              <CartesianGrid stroke="#223055" strokeDasharray="3 3" />
              <XAxis dataKey="t" tickFormatter={(t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} stroke="#8ba0c7" fontSize={10} />
              <YAxis stroke="#8ba0c7" fontSize={10} />
              <Tooltip contentStyle={{ background: "#131c33", border: "1px solid #223055", borderRadius: 8 }} />
              <Area type="monotone" dataKey="value" stroke="#22c55e" fill="rgba(34,197,94,.2)" name="auth events" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <Card title="Severity distribution">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80} label>
                {severityData.map((e, i) => <Cell key={i} fill={e.fill} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#131c33", border: "1px solid #223055", borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Top source IPs">
          {d.top_source_ips.length === 0 ? <Empty text="No source IPs in window" /> : (
            <table>
              <thead><tr><th>IP</th><th style={{ textAlign: "right" }}>Events</th></tr></thead>
              <tbody>
                {d.top_source_ips.map((r) => (
                  <tr key={r.ip}><td className="mono">{r.ip}</td><td style={{ textAlign: "right" }}>{r.count}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Top affected assets">
          {d.top_assets.length === 0 ? <Empty text="No asset activity in window" /> : (
            <table>
              <thead><tr><th>Asset</th><th style={{ textAlign: "right" }}>Events</th></tr></thead>
              <tbody>
                {d.top_assets.map((r) => (
                  <tr key={r.device}><td className="mono">{r.device}</td><td style={{ textAlign: "right" }}>{r.count}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="grid cols-3">
        <Card title="Event types">
          {eventTypeData.length === 0 ? <Empty text="No events in window" /> : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={eventTypeData} layout="vertical" margin={{ left: 8 }}>
                <CartesianGrid stroke="#223055" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke="#8ba0c7" fontSize={10} />
                <YAxis type="category" dataKey="name" width={130} stroke="#8ba0c7" fontSize={10} />
                <Tooltip contentStyle={{ background: "#131c33", border: "1px solid #223055", borderRadius: 8 }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card title="Incident status">
          {incidentData.length === 0 ? <Empty text="No incidents yet" /> : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={incidentData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80} label>
                  <Cell fill="#ef4444" /><Cell fill="#f97316" /><Cell fill="#a855f7" /><Cell fill="#22c55e" /><Cell fill="#8ba0c7" />
                </Pie>
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#131c33", border: "1px solid #223055", borderRadius: 8 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card title="Top users">
          {d.top_users.length === 0 ? <Empty text="No user activity in window" /> : (
            <table>
              <thead><tr><th>User</th><th style={{ textAlign: "right" }}>Events</th></tr></thead>
              <tbody>
                {d.top_users.map((r) => (
                  <tr key={r.username}><td className="mono">{r.username}</td><td style={{ textAlign: "right" }}>{r.count}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {d.alert_status_distribution && Object.keys(d.alert_status_distribution).length > 0 && (
        <Card title="Alert queue status" className="" >
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
            {Object.entries(d.alert_status_distribution).map(([k, v]) => (
              <div key={k}><span className={`pill st-${k.replace(/\s+/g, "_")}`}>{k}</span> <b>{v}</b></div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
