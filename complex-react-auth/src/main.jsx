import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API_ROOT = ['/', ['a', 'p', 'i'].join('')].join('');

function apiPath(...segments) {
  return API_ROOT + '/' + segments.join('/');
}

function authHeader() {
  const token = localStorage.getItem('access_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function authenticatedFetch(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...authHeader(),
    },
  });

  if (response.status === 401) {
    localStorage.removeItem('access_token');
    window.location.hash = '#/login';
  }
  return response;
}

function Login({ onAuthenticated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');

    try {
      const response = await fetch(apiPath('auth', 'login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const body = await response.json();
      if (!response.ok || !body.access_token) {
        setError(body.error || 'Authentication failed');
        return;
      }

      localStorage.setItem('access_token', body.access_token);
      const verify = await authenticatedFetch(apiPath('auth', 'currentUser'));
      if (!verify.ok) {
        setError('Token was issued but protected API rejected it');
        return;
      }

      window.location.hash = '#/dashboard';
      onAuthenticated(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-layout">
      <section className="login-card">
        <h1>Complex React Auth</h1>
        <p className="muted">
          The form looks conventional, but React intercepts submit and sends JSON. No session cookie is created.
        </p>
        <form onSubmit={submit} autoComplete="on">
          <label>
            Login
            <input
              name="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          <button id="login-submit" type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        {error && <div className="error" id="login-error">{error}</div>}
      </section>
    </main>
  );
}

function MenuItem({ children, onClick, className = '', role }) {
  return (
    <div
      className={`menu-item ${className}`}
      role={role}
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') onClick();
      }}
    >
      {children}
    </div>
  );
}

function Application({ onLoggedOut }) {
  const [operationsOpen, setOperationsOpen] = useState(false);
  const [documentsOpen, setDocumentsOpen] = useState(false);
  const [result, setResult] = useState('Choose an item from the DIV-based navigation.');
  const [route, setRoute] = useState(window.location.hash || '#/dashboard');

  async function openView(routeName, endpointSegments, query = '') {
    window.location.hash = '#/' + routeName;
    setRoute('#/' + routeName);
    const path = apiPath(...endpointSegments) + query;
    const response = await authenticatedFetch(path);
    const text = await response.text();
    setResult(`${response.status} ${path}\n${text}`);
    if (response.status === 401) onLoggedOut();
  }

  useEffect(() => {
    const handler = () => setRoute(window.location.hash || '#/dashboard');
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);

  useEffect(() => {
    openView('dashboard', ['dashboard'], '?source=initial');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">Complex Portal</div>

        <MenuItem onClick={() => openView('dashboard', ['dashboard'], '?source=menu')}>
          Dashboard
        </MenuItem>

        <MenuItem className="dropdown-root" onClick={() => setOperationsOpen((v) => !v)}>
          Operations <span>{operationsOpen ? '▾' : '▸'}</span>
        </MenuItem>

        {operationsOpen && (
          <div className="submenu">
            <MenuItem onClick={() => openView('orders', [['ord', 'ers'].join('')], '?status=open')}>
              Orders
            </MenuItem>

            <MenuItem onClick={() => setDocumentsOpen((v) => !v)}>
              Documents <span>{documentsOpen ? '▾' : '▸'}</span>
            </MenuItem>

            {documentsOpen && (
              <div className="submenu nested">
                <MenuItem onClick={() => openView('contracts', [['con', 'tracts'].join('')], '?customer=42')}>
                  Contracts
                </MenuItem>
                <MenuItem onClick={() => openView('archive', [['ar', 'chive'].join('')], '?folder=2026')}>
                  Archive
                </MenuItem>
              </div>
            )}
          </div>
        )}

        <MenuItem
          role="menuitem"
          onClick={() => openView('customers', [['cus', 'tomers'].join('')], '?id=42')}
        >
          Customers
        </MenuItem>

        <MenuItem onClick={() => openView('reports', [['rep', 'orts'].join('')], '?period=30d')}>
          Reports
        </MenuItem>

        <div className="menu-note">
          Navigation intentionally uses DIV elements instead of anchors or navigation buttons.
        </div>
      </aside>

      <main className="content">
        <div className="toolbar">
          <strong>{route}</strong>
          <div className="token-state">Bearer token is read from localStorage</div>
        </div>
        <section className="panel">
          <h2>Protected view</h2>
          <pre id="api-result">{result}</pre>
        </section>
      </main>
    </div>
  );
}

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    async function bootstrap() {
      const token = localStorage.getItem('access_token');
      if (!token) {
        window.location.hash = '#/login';
        setReady(true);
        return;
      }

      try {
        const response = await authenticatedFetch(apiPath('auth', 'currentUser'));
        setAuthenticated(response.ok);
        if (!response.ok) window.location.hash = '#/login';
      } finally {
        setReady(true);
      }
    }
    bootstrap();
  }, []);

  if (!ready) return <div className="loading">Loading…</div>;
  if (!authenticated) return <Login onAuthenticated={setAuthenticated} />;
  return <Application onLoggedOut={() => setAuthenticated(false)} />;
}

createRoot(document.getElementById('root')).render(<App />);
