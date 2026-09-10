import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../services/api';
import { User } from '../types';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [identifier, setIdentifier] = useState('admin@sentinelai.local');
  const [password, setPassword] = useState('SentinelDemo!2026');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [forgotMsg, setForgotMsg] = useState('');
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotIdentifier, setForgotIdentifier] = useState('');
  const [forgotLoading, setForgotLoading] = useState(false);
  const [resetTokenData, setResetTokenData] = useState<{ token: string; email?: string } | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [resetSuccessMsg, setResetSuccessMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await api<{ access_token: string; user: User }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          identifier: identifier.trim(),
          password,
          remember_me: rememberMe,
        }),
      });
      localStorage.setItem('token', res.access_token);
      localStorage.setItem('user', JSON.stringify(res.user));
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotLoading(true);
    setForgotMsg('');
    try {
      const res = await api<{ status: string; detail: string; reset_token?: string; email?: string }>('/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ identifier: forgotIdentifier.trim() }),
      });
      if (res.reset_token) {
        setResetTokenData({ token: res.reset_token, email: res.email });
        setForgotMsg('Reset token generated successfully.');
      } else {
        setForgotMsg(res.detail || 'If an account exists, a reset token was created.');
      }
    } catch (err: any) {
      setForgotMsg(err.message || 'Error requesting password reset');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTokenData?.token) return;
    setForgotLoading(true);
    try {
      const res = await api<{ status: string; detail: string }>('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({ token: resetTokenData.token, new_password: newPassword }),
      });
      setResetSuccessMsg(res.detail || 'Password reset complete! You can now log in.');
      setResetTokenData(null);
      setPassword(newPassword);
    } catch (err: any) {
      setForgotMsg(err.message || 'Failed to reset password');
    } finally {
      setForgotLoading(false);
    }
  };

  const setPreset = (id: string, pass: string) => {
    setIdentifier(id);
    setPassword(pass);
    setError('');
  };

  return (
    <div className="auth-wrapper">
      <div className="auth-box" style={{ maxWidth: '440px', width: '100%' }}>
        <div className="auth-header">
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(0, 243, 255, 0.1)', border: '1px solid rgba(0, 243, 255, 0.3)', marginBottom: '12px' }}>
            <span style={{ fontSize: '24px', color: 'var(--cyan)' }}>◈</span>
          </div>
          <h1 style={{ margin: 0, fontSize: '24px', letterSpacing: '0.1em' }}>SENTINELAI</h1>
          <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: 'var(--text-dim)' }}>Autonomous SOC Operations & Incident Response Assistant</p>
        </div>

        {error && <div className="error-banner" style={{ marginBottom: '14px' }}>{error}</div>}
        {resetSuccessMsg && <div className="badge-pill" style={{ background: 'rgba(0, 255, 157, 0.15)', color: 'var(--neon-green)', padding: '8px 12px', borderRadius: '6px', marginBottom: '14px', textAlign: 'center' }}>{resetSuccessMsg}</div>}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="form-group">
            <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Username or Account Email</label>
            <input
              type="text"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              placeholder="e.g. admin or analyst@sentinelai.local"
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', margin: 0 }}>Master Password</label>
              <button
                type="button"
                onClick={() => { setShowForgotModal(true); setForgotIdentifier(identifier); setForgotMsg(''); setResetSuccessMsg(''); }}
                style={{ background: 'none', border: 'none', color: 'var(--cyan)', fontSize: '11px', cursor: 'pointer', padding: 0 }}
              >
                Forgot Password?
              </button>
            </div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text-muted)' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{ cursor: 'pointer' }}
              />
              Remember me (30-day session)
            </label>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ marginTop: '6px', padding: '12px', fontWeight: 600, letterSpacing: '0.05em' }}
          >
            {loading ? 'Authenticating…' : 'Authenticate & Enter SOC →'}
          </button>
        </form>

        <div style={{ marginTop: '16px', textAlign: 'center', fontSize: '12px', color: 'var(--text-muted)' }}>
          Don't have an account?{' '}
          <Link to="/register" style={{ color: 'var(--cyan)', fontWeight: 600, textDecoration: 'none' }}>
            Create Account
          </Link>
        </div>

        <div style={{ marginTop: '20px', paddingTop: '14px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-dim)', marginBottom: '8px', textAlign: 'center' }}>
            Quick Demo Presets
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            <button
              type="button"
              onClick={() => setPreset('admin@sentinelai.local', 'SentinelDemo!2026')}
              className="btn btn-secondary"
              style={{ fontSize: '11px', padding: '6px 8px' }}
            >
              👑 Admin Demo
            </button>
            <button
              type="button"
              onClick={() => setPreset('admin', 'SentinelDemo!2026')}
              className="btn btn-secondary"
              style={{ fontSize: '11px', padding: '6px 8px' }}
            >
              🛡️ Username Demo
            </button>
          </div>
        </div>
      </div>

      {/* Forgot / Reset Password Modal */}
      {showForgotModal && (
        <div className="modal-overlay" onClick={() => setShowForgotModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '460px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <h3 style={{ margin: 0, color: 'var(--cyan)' }}>🔑 Account Password Recovery</h3>
              <button onClick={() => setShowForgotModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '16px' }}>✕</button>
            </div>

            {forgotMsg && <div className="badge-pill" style={{ background: 'rgba(0, 243, 255, 0.1)', color: 'var(--cyan)', padding: '8px 12px', borderRadius: '6px', marginBottom: '12px', fontSize: '11px' }}>{forgotMsg}</div>}

            {!resetTokenData ? (
              <form onSubmit={handleForgotPassword} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>
                  Enter your registered username or email to generate a secure recovery token:
                </p>
                <div className="form-group">
                  <label>Username or Email</label>
                  <input
                    type="text"
                    value={forgotIdentifier}
                    onChange={(e) => setForgotIdentifier(e.target.value)}
                    placeholder="e.g. admin or username"
                    required
                  />
                </div>
                <button type="submit" disabled={forgotLoading} className="btn btn-primary" style={{ padding: '10px' }}>
                  {forgotLoading ? 'Processing…' : 'Generate Recovery Token →'}
                </button>
              </form>
            ) : (
              <form onSubmit={handleResetPassword} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '6px', fontSize: '11px' }}>
                  <div><strong>Account:</strong> {resetTokenData.email || forgotIdentifier}</div>
                  <div style={{ marginTop: '4px', wordBreak: 'break-all' }}><strong>Token:</strong> <code>{resetTokenData.token}</code></div>
                </div>
                <div className="form-group">
                  <label>Enter New Password (min 8 characters)</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="••••••••••••"
                    required
                    minLength={8}
                  />
                </div>
                <button type="submit" disabled={forgotLoading} className="btn btn-primary" style={{ padding: '10px' }}>
                  {forgotLoading ? 'Saving…' : 'Confirm New Password & Unlock Account'}
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
