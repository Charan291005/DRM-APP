import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api';
import { format, parseISO } from 'date-fns';
import { ArrowLeft, Shield, CheckCircle, XCircle } from 'lucide-react';
import { Doughnut, Line } from 'react-chartjs-2';

export default function FileDetails() {
  const { id } = useParams();
  const [file, setFile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const files = await api.getFiles();
        const f = files.find(x => x.id === id);
        setFile(f);
        
        const logsData = await api.getAuditLogs(id);
        setLogs(logsData);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [id]);

  if (loading) return <div>Loading details...</div>;
  if (!file) return <div>File not found</div>;

  // Calculate stats
  const successfulAccesses = logs.filter(l => l.status === 'OK' && l.action === 'DECRYPT').length;
  const deniedAccesses = logs.filter(l => l.status !== 'OK' && l.action === 'DECRYPT').length;

  const chartData = {
    labels: ['Successful', 'Denied'],
    datasets: [
      {
        data: [successfulAccesses, deniedAccesses],
        backgroundColor: ['#10B981', '#EF4444'],
        borderColor: ['#064E3B', '#7F1D1D'],
        borderWidth: 1,
      },
    ],
  };

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <Link to="/" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', color: 'var(--text-3)', marginBottom: '1rem' }}>
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1 style={{ fontSize: '2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '12px' }}>
              {file.original_name}
              {file.is_revoked ? (
                <span className="badge badge-error">Revoked</span>
              ) : (
                <span className="badge badge-success">Active</span>
              )}
            </h1>
            <p className="mono" style={{ color: 'var(--text-3)', fontSize: '0.875rem' }}>File ID: {file.id}</p>
          </div>
          
          {!file.is_revoked && (
            <button 
              className="btn btn-danger"
              onClick={async () => {
                if(window.confirm('Revoke access immediately?')) {
                  await api.revokeFile(file.id);
                  window.location.reload();
                }
              }}
            >
              <Shield size={16} /> Revoke Access
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>
        <div className="glass-card" style={{ padding: '2rem' }}>
          <h3 style={{ marginBottom: '1.5rem', color: 'var(--text-2)' }}>File Policies</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: '0.25rem' }}>Expiry Date</div>
              <div style={{ fontSize: '1.125rem', fontWeight: '500' }}>{format(parseISO(file.expiry_dt), 'MMM d, yyyy HH:mm')}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: '0.25rem' }}>Device Lock</div>
              <div style={{ fontSize: '1.125rem', fontWeight: '500' }}>
                {file.lock_type === 'NONE' ? 'None' : `${file.lock_type} (${file.lock_identifier})`}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: '0.25rem' }}>Watermark</div>
              <div style={{ fontSize: '1.125rem', fontWeight: '500' }}>
                {file.watermark_text ? `${file.watermark_text} (${file.watermark_opacity}%)` : 'None'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: '0.25rem' }}>File Size</div>
              <div style={{ fontSize: '1.125rem', fontWeight: '500' }}>
                {file.file_size_bytes ? `${(file.file_size_bytes / 1024).toFixed(1)} KB` : 'Unknown'}
              </div>
            </div>
          </div>
        </div>

        <div className="glass-card" style={{ padding: '2rem', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ marginBottom: '1.5rem', color: 'var(--text-2)' }}>Access Analytics</h3>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {logs.length > 0 ? (
               <div style={{ height: '200px', width: '200px' }}>
                 <Doughnut data={chartData} options={{ maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#F1F5F9' } } } }} />
               </div>
            ) : (
              <p style={{ color: 'var(--text-3)' }}>No decryption attempts yet.</p>
            )}
          </div>
        </div>
      </div>

      <div className="glass-card">
        <div style={{ padding: '1.5rem', borderBottom: '1px solid var(--bdr-sub)' }}>
          <h3 style={{ color: 'var(--text-1)' }}>Detailed Audit Log</h3>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan="6" style={{ textAlign: 'center', padding: '2rem' }}>No activity logs found.</td></tr>
            ) : (
              logs.map(log => (
                <tr key={log.id}>
                  <td>{format(parseISO(log.created_at), 'MMM d, yyyy HH:mm:ss')}</td>
                  <td><span className="badge badge-accent">{log.action}</span></td>
                  <td className="mono">{log.ip_address || '-'}</td>
                  <td className="mono">{log.mac_address || '-'}</td>
                  <td>
                    {log.status === 'OK' ? (
                      <span style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <CheckCircle size={14} /> OK
                      </span>
                    ) : (
                      <span style={{ color: 'var(--error)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <XCircle size={14} /> DENIED
                      </span>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-3)' }}>{log.details || '-'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
