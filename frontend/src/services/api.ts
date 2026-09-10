const API_BASE = 'http://127.0.0.1:8000/api/v1';

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> || {}),
  };

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errMsg = response.statusText;
    try {
      const data = await response.json();
      errMsg = data.detail || (Array.isArray(data.detail) ? data.detail.map((d: any) => d.msg).join(', ') : JSON.stringify(data));
    } catch {
      // fallback
    }
    throw new Error(errMsg || `Request failed with status ${response.status}`);
  }

  return response.json();
}

export async function uploadLogFile(file: File): Promise<any> {
  const token = localStorage.getItem('token');
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/logs/upload`, {
    method: 'POST',
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: formData,
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(data.detail || 'Log upload failed');
  }

  return response.json();
}

export async function downloadPdf(path: string, filename: string): Promise<void> {
  const token = localStorage.getItem('token');
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!response.ok) {
    throw new Error('Failed to generate PDF report');
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}
