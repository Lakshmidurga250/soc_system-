import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

const BASE_NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: '◈' },
  { path: '/events', label: 'Live Events', icon: '☵' },
  { path: '/alerts', label: 'Alerts & Triage', icon: '⚠' },
  { path: '/incidents', label: 'Incidents & Forensics', icon: '⚡' },
  { path: '/threat-intel', label: 'Threat Intelligence', icon: '☣' },
  { path: '/detection', label: 'Detection Rules', icon: '⚙' },
  { path: '/response', label: 'Response & Approvals', icon: '🛡' },
  { path: '/reports', label: 'Forensic Reports', icon: '📄' },
  { path: '/system-health', label: 'System & ML Engine', icon: '♥' },
];

export const Navigation: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const userJson = localStorage.getItem('user');
  const user = userJson ? JSON.parse(userJson) : null;
  const isAdmin = user?.role === 'ADMIN';

  const navItems = [
    ...BASE_NAV_ITEMS,
    ...(isAdmin ? [{ path: '/users', label: 'User Management', icon: '👥' }] : []),
    { path: '/profile', label: 'User Profile', icon: '👤' },
  ];

  const handleSignOut = () => {
    localStorage.clear();
    navigate('/login');
  };

  const initial = (user?.full_name || user?.username || 'A').charAt(0).toUpperCase();

  return (
    <aside className="sidebar">
      <div className="brand-logo">
        <span className="symbol">◈</span>
        <div>
          <h1>SENTINELAI</h1>
          <span>AUTONOMOUS SOC</span>
        </div>
      </div>

      <nav className="nav-links">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${isActive ? 'active' : ''}`}
            >
              <span style={{ fontSize: '15px' }}>{item.icon}</span>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <Link to="/profile" style={{ textDecoration: 'none', color: 'inherit', display: 'block', marginBottom: '8px' }}>
          <div className="user-status" style={{ cursor: 'pointer' }}>
            <div className="avatar">{initial}</div>
            <div className="user-details">
              <span className="name">{user?.full_name || 'SOC Analyst'}</span>
              <span className="role">ROLE: {user?.role || 'SOC_ANALYST'}</span>
            </div>
          </div>
        </Link>
        <button onClick={handleSignOut} className="btn-signout">
          Sign Out of Workspace
        </button>
      </div>
    </aside>
  );
};
