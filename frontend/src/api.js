export const API_URL = "http://localhost:8000";

const getHeaders = () => {
  const token = localStorage.getItem("token");
  return {
    "Content-Type": "application/json",
    ...(token && { Authorization: `Bearer ${token}` }),
  };
};

export const api = {
  async login(email, password) {
    const res = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Login failed");
    return data;
  },

  async register(email, password, full_name) {
    const res = await fetch(`${API_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, full_name }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Registration failed");
    return data;
  },

  async getMe() {
    const res = await fetch(`${API_URL}/auth/me`, { headers: getHeaders() });
    if (!res.ok) throw new Error("Unauthorized");
    return res.json();
  },

  async getFiles() {
    const res = await fetch(`${API_URL}/files/`, { headers: getHeaders() });
    if (!res.ok) throw new Error("Failed to fetch files");
    return res.json();
  },

  async revokeFile(id) {
    const res = await fetch(`${API_URL}/files/${id}/revoke`, {
      method: "PATCH",
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error("Failed to revoke file");
    return res.json();
  },

  async getAuditLogs(fileId = "") {
    const url = fileId ? `${API_URL}/audit/${fileId}` : `${API_URL}/audit/`;
    const res = await fetch(url, { headers: getHeaders() });
    if (!res.ok) throw new Error("Failed to fetch audit logs");
    return res.json();
  }
};
