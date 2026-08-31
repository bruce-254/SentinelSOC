import React from "react";
import { Routes, Route, Navigate, NavLink, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "./auth";

import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Rules from "./pages/Rules";
import Assets from "./pages/Assets";
import Risk from "./pages/Risk";
import Reports from "./pages/Reports";
import Audit from "./pages/Audit";
import ThreatIntel from "./pages/ThreatIntel";
import Users from "./pages/Users";
import Search from "./pages/Search";

const NAV = [
  { group: "Operations", items: [
    { to: "/", label: "Dashboard", ic: "📊", end: true },
    { to: "/search", label: "Search", ic: "🔍" },
    { to: "/events", label: "Events", ic: "🧾" },
    { to: "/alerts", label: "Alerts", ic: "🚨" },
    { to: "/incidents", label: "Incidents", ic: "🛠️" },
  ]},
  { group: "Defense", items: [
    { to: "/rules", label: "Detection Rules", ic: "📏" },
    { to: "/risk", label: "Risk Scoring", ic: "🎯" },
    { to: "/assets", label: "Assets", ic: "🖥️" },
    { to: "/threatintel", label: "Threat Intel", ic: "🌐" },
  ]},
  { group: "Governance", items: [
    { to: "/reports", label: "Reports", ic: "📄" },
    { to: "/audit", label: "Audit Log", ic: "📜" },
    { to: "/users", label: "Users & Roles", ic: "👥" },
  ]},
];

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="logo">🛡️</span>
        <div><b>SentinelSOC</b><span>Security Operations</span></div>
      </div>
      <nav>
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="group">{g.group}</div>
            {g.items.map((it) => (
              <NavLink
                key={it.to}
                to={it.to}
                end={it.end}
                className={({ isActive }) => "nav-item" + (isActive ? " active" : "")}
              >
                <span className="ic">{it.ic}</span> {it.label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="foot">Defensive SOC platform<br />v1.0.0</div>
    </aside>
  );
}

function Topbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const loc = useLocation();
  const current = NAV.flatMap((g) => g.items).find((i) =>
    i.end ? loc.pathname === i.to : loc.pathname.startsWith(i.to)
  );
  return (
    <header className="topbar">
      <div className="title">{current ? current.label : "SentinelSOC"}</div>
      <div className="user">
        <span>{user?.organization_name || ""}</span>
        <span className="badge-role">{user?.role || "guest"}</span>
        <div className="avatar">{(user?.username || "?").slice(0, 1).toUpperCase()}</div>
        <span>{user?.username || ""}</span>
        <button className="btn small" onClick={() => { logout(); navigate("/login"); }}>Sign out</button>
      </div>
    </header>
  );
}

function Shell({ children }) {
  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <Topbar />
        <div className="content">{children}</div>
      </div>
    </div>
  );
}

function RequireAuth({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="empty">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <Shell>{children}</Shell>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
      <Route path="/search" element={<RequireAuth><Search /></RequireAuth>} />
      <Route path="/events" element={<RequireAuth><Events /></RequireAuth>} />
      <Route path="/alerts" element={<RequireAuth><Alerts /></RequireAuth>} />
      <Route path="/alerts/:id" element={<RequireAuth><AlertDetail /></RequireAuth>} />
      <Route path="/incidents" element={<RequireAuth><Incidents /></RequireAuth>} />
      <Route path="/incidents/:id" element={<RequireAuth><IncidentDetail /></RequireAuth>} />
      <Route path="/rules" element={<RequireAuth><Rules /></RequireAuth>} />
      <Route path="/risk" element={<RequireAuth><Risk /></RequireAuth>} />
      <Route path="/assets" element={<RequireAuth><Assets /></RequireAuth>} />
      <Route path="/reports" element={<RequireAuth><Reports /></RequireAuth>} />
      <Route path="/audit" element={<RequireAuth><Audit /></RequireAuth>} />
      <Route path="/threatintel" element={<RequireAuth><ThreatIntel /></RequireAuth>} />
      <Route path="/users" element={<RequireAuth><Users /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
