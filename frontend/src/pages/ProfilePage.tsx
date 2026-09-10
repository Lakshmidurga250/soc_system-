import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { User } from '../types';

export const ProfilePage: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [themeDark, setThemeDark] = useState(true);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [passwordMsg, setPasswordMsg] = useState('');
  const [profileMsg, setProfileMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      const res = await api<User>('/auth/me');
      setUser(res);
      setFullName(res.full_name || '');
      setEmail(res.email || '');
      setUsername(res.username || '');
    } catch (err: any) {
      console.error('Failed to load user profile', err);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setProfileMsg('');
    setErrorMsg('');
    try {
      const updated = await api<User>('/auth/profile', {
        method: 'PATCH',
        body: JSON.stringify({
          full_name: fullName.trim(),
          email: email.trim(),
          username: username.trim().toLowerCase(),
          settings_json: {
            theme_dark: themeDark,
            notifications_enabled: notificationsEnabled,
          },
        }),
      });
      setUser(updated);
      localStorage.setItem('user', JSON.stringify(updated));
      setProfileMsg('Profile updated successfully.');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordMsg('');
    setErrorMsg('');

    if (newPassword.length < 8) {
      setErrorMsg('New password must be at least 8 characters long.');
      return;
    }

    if (newPassword !== confirmNewPassword) {
      setErrorMsg('New passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await api<{ status: string; detail: string }>('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });
      setPasswordMsg('Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container" style={{ maxWidth: '1000px', margin: '0 auto', padding: '24px' }}>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: 'var(--cyan)' }}>👤</span> User Profile & Security Settings
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: '4px 0 0 0' }}>
          Manage your analyst identity credentials, security posture, and platform preferences.
        </p>
      </div>

      {profileMsg && <div className="badge-pill" style={{ background: 'rgba(0, 255, 157, 0.15)', color: 'var(--neon-green)', padding: '10px 14px', borderRadius: '6px', marginBottom: '16px' }}>{profileMsg}</div>}
      {passwordMsg && <div className="badge-pill" style={{ background: 'rgba(0, 255, 157, 0.15)', color: 'var(--neon-green)', padding: '10px 14px', borderRadius: '6px', marginBottom: '16px' }}>{passwordMsg}</div>}
      {errorMsg && <div className="error-banner" style={{ marginBottom: '16px' }}>{errorMsg}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Account Identity Card */}
        <div className="card" style={{ padding: '20px', background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <h3 style={{ fontSize: '16px', margin: '0 0 16px 0', color: 'var(--cyan)', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            Personal Details & Identity
          </h3>

          <form onSubmit={handleUpdateProfile} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="form-group">
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Full Name</label>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Unique Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Email Address</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px', fontSize: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Assigned RBAC Role:</span>
                <span className="badge-pill" style={{ background: 'rgba(0, 243, 255, 0.1)', color: 'var(--cyan)', fontWeight: 600 }}>{user?.role || 'SOC_ANALYST'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Account Created:</span>
                <span>{user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Last Login:</span>
                <span>{user?.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'This session'}</span>
              </div>
            </div>

            <button type="submit" disabled={loading} className="btn btn-primary" style={{ padding: '10px' }}>
              {loading ? 'Saving…' : 'Save Profile Changes'}
            </button>
          </form>
        </div>

        {/* Change Password & Security Card */}
        <div className="card" style={{ padding: '20px', background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <h3 style={{ fontSize: '16px', margin: '0 0 16px 0', color: 'var(--cyan)', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            Security & Password Management
          </h3>

          <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="form-group">
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="••••••••••••"
                required
              />
            </div>

            <div className="form-group">
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>New Password (min 8 chars)</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                minLength={8}
              />
            </div>

            <div className="form-group">
              <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Confirm New Password</label>
              <input
                type="password"
                value={confirmNewPassword}
                onChange={(e) => setConfirmNewPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                minLength={8}
              />
            </div>

            <div style={{ fontSize: '11px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
              💡 Passwords are encrypted using high-security PBKDF2/Argon2 hashing with salted digests.
            </div>

            <button type="submit" disabled={loading} className="btn btn-secondary" style={{ padding: '10px', marginTop: 'auto' }}>
              {loading ? 'Updating…' : 'Update Password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
