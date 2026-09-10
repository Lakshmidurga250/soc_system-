import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { User } from '../types';

export const UsersManagementPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  // Selected user for role change or password reset
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [newRole, setNewRole] = useState('SOC_ANALYST');
  const [adminNewPassword, setAdminNewPassword] = useState('');
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [showPassModal, setShowPassModal] = useState(false);

  useEffect(() => {
    loadUsers();
  }, [search, roleFilter, activeFilter]);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.append('q', search);
      if (roleFilter) params.append('role', roleFilter);
      if (activeFilter !== '') params.append('is_active', activeFilter);

      const data = await api<User[]>(`/users?${params.toString()}`);
      setUsers(data);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  const handleRoleUpdate = async () => {
    if (!selectedUser) return;
    try {
      await api(`/users/${selectedUser.id}/role`, {
        method: 'PATCH',
        body: JSON.stringify({ role: newRole }),
      });
      setMsg(`Role updated to ${newRole} for ${selectedUser.username || selectedUser.email}`);
      setShowRoleModal(false);
      loadUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to update user role');
    }
  };

  const handleStatusToggle = async (user: User) => {
    try {
      await api(`/users/${user.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ is_active: !user.is_active }),
      });
      setMsg(`User ${user.username || user.email} status changed to ${!user.is_active ? 'ACTIVE' : 'DEACTIVATED'}`);
      loadUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle user status');
    }
  };

  const handleAdminResetPassword = async () => {
    if (!selectedUser || !adminNewPassword) return;
    try {
      await api(`/users/${selectedUser.id}/admin-reset-password`, {
        method: 'POST',
        body: JSON.stringify({ new_password: adminNewPassword }),
      });
      setMsg(`Password successfully reset for ${selectedUser.username || selectedUser.email}`);
      setShowPassModal(false);
      setAdminNewPassword('');
    } catch (err: any) {
      setError(err.message || 'Failed to reset password');
    }
  };

  return (
    <div className="page-container" style={{ maxWidth: '1200px', margin: '0 auto', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '24px', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--cyan)' }}>👥</span> Multi-User & Access Control Center
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: '4px 0 0 0' }}>
            Administrator console for managing SOC analysts, role permissions, and access states.
          </p>
        </div>
        <button onClick={loadUsers} className="btn btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          🔄 Refresh
        </button>
      </div>

      {msg && <div className="badge-pill" style={{ background: 'rgba(0, 255, 157, 0.15)', color: 'var(--neon-green)', padding: '10px 14px', borderRadius: '6px', marginBottom: '16px' }}>{msg}</div>}
      {error && <div className="error-banner" style={{ marginBottom: '16px' }}>{error}</div>}

      {/* Filters Bar */}
      <div className="card" style={{ padding: '16px', background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '10px', marginBottom: '20px', display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="🔍 Search users by name, username, or email…"
          style={{ flex: 1, minWidth: '240px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: '6px', color: 'var(--text)' }}
        />

        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: '6px', color: 'var(--text)' }}
        >
          <option value="">All Roles</option>
          <option value="ADMIN">ADMIN</option>
          <option value="SOC_ANALYST">SOC_ANALYST</option>
          <option value="VIEWER">VIEWER</option>
        </select>

        <select
          value={activeFilter}
          onChange={(e) => setActiveFilter(e.target.value)}
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: '6px', color: 'var(--text)' }}
        >
          <option value="">All Statuses</option>
          <option value="true">Active Only</option>
          <option value="false">Deactivated Only</option>
        </select>
      </div>

      {/* Users Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden', background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '10px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ background: 'rgba(255, 255, 255, 0.03)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>Analyst / User</th>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>Username</th>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>Email</th>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>Role</th>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>Status</th>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>Last Login</th>
              <th style={{ padding: '12px 16px', color: 'var(--text-muted)', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading user records…
                </td>
              </tr>
            ) : users.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No users found matching filter criteria.
                </td>
              </tr>
            ) : (
              users.map((u) => (
                <tr key={u.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 600 }}>{u.full_name}</td>
                  <td style={{ padding: '12px 16px' }}><code>@{u.username || 'n/a'}</code></td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>{u.email}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span className="badge-pill" style={{
                      background: u.role === 'ADMIN' ? 'rgba(255, 51, 102, 0.15)' : u.role === 'SOC_ANALYST' ? 'rgba(0, 243, 255, 0.15)' : 'rgba(255, 255, 255, 0.1)',
                      color: u.role === 'ADMIN' ? '#ff3366' : u.role === 'SOC_ANALYST' ? 'var(--cyan)' : 'var(--text-muted)',
                      padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600
                    }}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: '6px',
                      color: u.is_active ? 'var(--neon-green)' : '#ff3366', fontSize: '12px'
                    }}>
                      ● {u.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-muted)', fontSize: '12px' }}>
                    {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <button
                        onClick={() => { setSelectedUser(u); setNewRole(u.role); setShowRoleModal(true); }}
                        className="btn btn-secondary"
                        style={{ fontSize: '11px', padding: '4px 8px' }}
                        title="Change Role"
                      >
                        Role
                      </button>
                      <button
                        onClick={() => handleStatusToggle(u)}
                        className="btn btn-secondary"
                        style={{ fontSize: '11px', padding: '4px 8px', color: u.is_active ? '#ff3366' : 'var(--neon-green)' }}
                        title="Toggle Active"
                      >
                        {u.is_active ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        onClick={() => { setSelectedUser(u); setAdminNewPassword(''); setShowPassModal(true); }}
                        className="btn btn-secondary"
                        style={{ fontSize: '11px', padding: '4px 8px' }}
                        title="Admin Reset Password"
                      >
                        🔑 Reset
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Role Change Modal */}
      {showRoleModal && selectedUser && (
        <div className="modal-overlay" onClick={() => setShowRoleModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
            <h3 style={{ margin: '0 0 12px 0', color: 'var(--cyan)' }}>Update Role for {selectedUser.full_name}</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Select the RBAC role authorization level for <code>@{selectedUser.username || selectedUser.email}</code>:
            </p>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '10px', borderRadius: '6px', color: 'var(--text)', marginBottom: '16px' }}
            >
              <option value="ADMIN">ADMIN (Full Platform Authority)</option>
              <option value="SOC_ANALYST">SOC_ANALYST (Triage, Analysis & Response)</option>
              <option value="VIEWER">VIEWER (Read-Only Access)</option>
            </select>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button onClick={() => setShowRoleModal(false)} className="btn btn-secondary">Cancel</button>
              <button onClick={handleRoleUpdate} className="btn btn-primary">Save Role</button>
            </div>
          </div>
        </div>
      )}

      {/* Password Reset Modal */}
      {showPassModal && selectedUser && (
        <div className="modal-overlay" onClick={() => setShowPassModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
            <h3 style={{ margin: '0 0 12px 0', color: 'var(--cyan)' }}>Admin Password Reset</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Directly set a new password for <strong>{selectedUser.full_name}</strong> (<code>@{selectedUser.username || selectedUser.email}</code>):
            </p>
            <input
              type="password"
              value={adminNewPassword}
              onChange={(e) => setAdminNewPassword(e.target.value)}
              placeholder="Minimum 8 characters"
              style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '10px', borderRadius: '6px', color: 'var(--text)', marginBottom: '16px' }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button onClick={() => setShowPassModal(false)} className="btn btn-secondary">Cancel</button>
              <button onClick={handleAdminResetPassword} className="btn btn-primary" disabled={adminNewPassword.length < 8}>
                Update Password
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
