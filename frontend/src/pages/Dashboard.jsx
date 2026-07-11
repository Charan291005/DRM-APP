import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { FileText, Clock, Ban, CheckCircle, Search, ShieldAlert } from 'lucide-react';
import { format, isPast, parseISO } from 'date-fns';

export default function Dashboard() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchFiles = async () => {
    try {
      const data = await api.getFiles();
      setFiles(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleRevoke = async (id) => {
    if (!window.confirm("Are you sure you want to revoke access to this file? All future decryptions will fail.")) return;
    try {
      await api.revokeFile(id);
      fetchFiles();
    } catch (e) {
      alert("Revocation failed: " + e.message);
    }
  };

  const filteredFiles = files.filter(f => 
    f.original_name.toLowerCase().includes(search.toLowerCase())
  );

  const getStatusBadge = (file) => {
    if (file.is_revoked) {
      return <span className="badge badge-error"><Ban size={12} style={{marginRight:'4px'}}/> Revoked</span>;
    }
    if (file.expiry_dt && isPast(parseISO(file.expiry_dt))) {
      return <span className="badge badge-neutral"><Clock size={12} style={{marginRight:'4px'}}/> Expired</span>;
    }
    return <span className="badge badge-success"><CheckCircle size={12} style={{marginRight:'4px'}}/> Active</span>;
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Dashboard</h1>
          <p style={{ color: 'var(--text-2)' }}>Manage your protected files and monitor access.</p>
        </div>
      </div>

      <div className="glass-card" style={{ marginBottom: '2rem', padding: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Search size={20} color="var(--text-3)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
          <input 
            type="text" 
            placeholder="Search files by name..." 
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ paddingLeft: '3rem', background: 'var(--bg-surface)' }}
          />
        </div>
      </div>

      <div className="glass-card">
        <table className="data-table">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Protected On</th>
              <th>Status</th>
              <th>Lock Policy</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="5" style={{ textAlign: 'center', padding: '3rem' }}>Loading files...</td></tr>
            ) : filteredFiles.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '4rem 1rem' }}>
                  <ShieldAlert size={48} color="var(--text-3)" style={{ margin: '0 auto', marginBottom: '1rem' }} />
                  <p style={{ color: 'var(--text-2)', fontSize: '1.1rem' }}>No protected files found.</p>
                  <p style={{ color: 'var(--text-3)', fontSize: '0.875rem', marginTop: '0.5rem' }}>
                    Use the DRM Guard Desktop App to encrypt and upload files.
                  </p>
                </td>
              </tr>
            ) : (
              filteredFiles.map(f => (
                <tr key={f.id}>
                  <td className="highlight">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <FileText size={20} color="var(--accent)" />
                      {f.original_name}
                    </div>
                  </td>
                  <td>{format(parseISO(f.created_at), 'MMM d, yyyy HH:mm')}</td>
                  <td>{getStatusBadge(f)}</td>
                  <td>
                    {f.lock_type === 'NONE' ? (
                      <span style={{ color: 'var(--text-3)' }}>No Device Lock</span>
                    ) : (
                      <span className="mono" style={{ color: 'var(--text-2)' }}>{f.lock_type}: {f.lock_identifier}</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                      <Link to={`/file/${f.id}`} className="btn btn-secondary" style={{ padding: '0.375rem 0.75rem' }}>
                        View Details
                      </Link>
                      {!f.is_revoked && (
                        <button onClick={() => handleRevoke(f.id)} className="btn btn-danger" style={{ padding: '0.375rem 0.75rem' }}>
                          Revoke
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
