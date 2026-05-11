import { Outlet, Link, useLocation } from 'react-router-dom';

function TopNav() {
  const { pathname } = useLocation();
  return (
    <nav className="top-nav glass-panel" aria-label="Primary">
      <Link to="/" className="nav-brand">
        <span className="nav-brand-mark" aria-hidden>🔐</span>
        <span>
          <span className="nav-brand-title">Medical Vault</span>
          <span className="nav-brand-sub">Zero-knowledge demo</span>
        </span>
      </Link>
      <div className="nav-links">
        <Link to="/" className={pathname === '/' ? 'active' : undefined}>
          Vault
        </Link>
        <Link to="/status" className={pathname === '/status' ? 'active' : undefined}>
          Live status
        </Link>
      </div>
    </nav>
  );
}

export default function Shell() {
  return (
    <div className="shell">
      <TopNav />
      <Outlet />
    </div>
  );
}
