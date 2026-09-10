import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../services/api';
import { User } from '../types';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [roleRequested, setRoleRequested] = useState('SOC_ANALYST');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Compute password strength score (0 to 4)
  const getPasswordStrength = (pwd: string) => {
    let score = 0;
    if (pwd.length >= 8) score++;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    return score;
  };

  const strength = getPasswordStrength(password);
  const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Secure'];
  const strengthColors = ['#ff3366', '#ff9900', '#ffea00', '#00f3ff', '#00ff9d'];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (username.length < 3) {
      setError('Username must be at least 3 characters long.');
      return;
    }

    if (!/^[a-zA-Z0-9_\-\.]+$/.test(username)) {
      setError('Username can only contain alphanumeric characters, underscores, hyphens, and dots.');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match. Please re-enter.');
      return;
    }

    setLoading(true);
    try {
      const res = await api<{ access_token: string; user: User }>('/auth/signup', {
        method: 'POST',
        body: JSON.stringify({
          full_name: fullName.trim(),
          username: username.trim().toLowerCase(),
          email: email.trim().toLowerCase(),
          password,
          role_requested: roleRequested,
        }),
      });

      localStorage.setItem('token', res.access_token);
      localStorage.setItem('user', JSON.stringify(res.user));
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please check your details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-wrapper">
      <div className="auth-box" style={{ maxWidth: '480px', width: '100%' }}>
        <div className="auth-header">
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(0, 243, 255, 0.1)', border: '1px solid rgba(0, 243, 255, 0.3)', marginBottom: '12px' }}>
            <span style={{ fontSize: '24px', color: 'var(--cyan)' }}>◈</span>
          </div>
          <h1 style={{ margin: 0, fontSize: '22px', letterSpacing: '0.1em' }}>CREATE SOC ACCOUNT</h1>
          <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: 'var(--text-dim)' }}>Register an analyst account for SentinelAI Platform</p>
        </div>

        {error && <div className="error-banner" style={{ marginBottom: '14px' }}>{error}</div>}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div className="form-group">
            <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Full Name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="e.g. Alex Mercer"
              required
              autoFocus
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div className="form-group">
              <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Unique Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/\s+/g, ''))}
                placeholder="e.g. alex_soc"
                required
              />
            </div>

            <div className="form-group">
              <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Role Requested</label>
              <select
                value={roleRequested}
                onChange={(e) => setRoleRequested(e.target.value)}
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text)', padding: '10px', borderRadius: '6px' }}
              >
                <option value="SOC_ANALYST">SOC Analyst (Tier 1/2)</option>
                <option value="VIEWER">Auditor / Viewer</option>
              </select>
            </div>
          </div>

          <div className="form-group">
            <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Corporate / Official Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="alex@sentinelai.local"
              required
            />
          </div>

          <div className="form-group">
            <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Minimum 8 characters"
              required
            />
            {password && (
              <div style={{ marginTop: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: strengthColors[strength], marginBottom: '3px' }}>
                  <span>Strength: {strengthLabels[strength]}</span>
                  <span>{strength * 25}%</span>
                </div>
                <div style={{ height: '4px', background: 'var(--border)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{ width: `${(strength + 1) * 20}%`, height: '100%', background: strengthColors[strength], transition: 'all 0.3s ease' }} />
                </div>
              </div>
            )}
          </div>

          <div className="form-group">
            <label style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Re-type password"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ marginTop: '6px', padding: '12px', fontWeight: 600, letterSpacing: '0.05em' }}
          >
            {loading ? 'Creating Account…' : 'Register Account & Enter SOC →'}
          </button>
        </form>

        <div style={{ marginTop: '16px', textAlign: 'center', fontSize: '12px', color: 'var(--text-muted)' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color: 'var(--cyan)', fontWeight: 600, textDecoration: 'none' }}>
            Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
};
