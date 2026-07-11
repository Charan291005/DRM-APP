import { NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, LogOut, Shield } from 'lucide-react';

export default function Sidebar() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <aside className="sidebar">
      <div style={{ padding: '2rem 1.5rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <Shield size={28} color="var(--accent)" />
        <h2 style={{ fontSize: '1.25rem' }}>DRM Guard</h2>
      </div>
      
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '0 1rem', flex: 1 }}>
        <NavLink 
          to="/" 
          style={({isActive}) => ({
            display: 'flex', alignItems: 'center', gap: '10px',
            padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)',
            color: isActive ? 'var(--accent)' : 'var(--text-2)',
            background: isActive ? 'var(--bg-card)' : 'transparent',
            fontWeight: isActive ? '600' : '500',
          })}
        >
          <LayoutDashboard size={20} />
          <span>Dashboard</span>
        </NavLink>
      </nav>

      <div style={{ padding: '1.5rem 1rem', borderTop: '1px solid var(--bdr-sub)' }}>
        <button 
          onClick={handleLogout}
          style={{
            display: 'flex', alignItems: 'center', gap: '10px',
            width: '100%', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)',
            background: 'transparent', color: 'var(--text-2)', 
            fontWeight: '500', transition: 'color 0.2s',
            textAlign: 'left'
          }}
          onMouseEnter={(e) => e.currentTarget.style.color = 'var(--error)'}
          onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-2)'}
        >
          <LogOut size={20} />
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
}
