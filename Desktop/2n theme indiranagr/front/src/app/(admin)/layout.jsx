"use client";

import React, { useContext, useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { AuthContext } from '../../context/AuthContext';
import { 
  FiHome, FiShoppingBag, FiMessageSquare, FiBox, 
  FiGrid, FiDroplet, FiImage, FiInfo, FiAward, 
  FiPhone, FiMessageCircle, FiSearch, FiLayout, FiLogOut,
  FiChevronDown, FiChevronRight
} from 'react-icons/fi';
import './AdminLayout.css';

const AdminLayout = ({ children }) => {
  const { logout, isAuthenticated, loading } = useContext(AuthContext);
  const [cmsOpen, setCmsOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  
  const location = usePathname();
  const router = useRouter();
  const pathnames = (location || '').split('/').filter((x) => x);

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      router.push('/admin/login');
    }
  }, [loading, isAuthenticated, router]);

  if (loading || !isAuthenticated) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>Loading...</div>;
  }

  return (
    <div className="admin-layout">
      {/* Sidebar */}
      <aside className="admin-sidebar">
        <div className="sidebar-header">
          <h2><FiBox style={{ marginRight: '8px', color: '#000000' }} /> Vapes Admin</h2>
        </div>
        
        <nav className="sidebar-nav">
          <ul>
            <li><Link href="/admin"><FiHome className="sidebar-icon" /> Dashboard</Link></li>
            <li><Link href="/admin/orders"><FiShoppingBag className="sidebar-icon" /> Orders</Link></li>
            <li><Link href="/admin/products"><FiBox className="sidebar-icon" /> Products</Link></li>
            <li><Link href="/admin/categories"><FiGrid className="sidebar-icon" /> Categories</Link></li>
            <li><Link href="/admin/manage-flavours"><FiDroplet className="sidebar-icon" /> Manage Flavours</Link></li>
            <li><Link href="/admin/enquiries"><FiMessageSquare className="sidebar-icon" /> Enquiries</Link></li>
            <li><Link href="/admin/banners"><FiImage className="sidebar-icon" /> Banners</Link></li>
            
            <li 
              className="sidebar-section clickable" 
              onClick={() => setCmsOpen(!cmsOpen)}
            >
              CMS Pages
              {cmsOpen ? <FiChevronDown className="section-icon" /> : <FiChevronRight className="section-icon" />}
            </li>
            {cmsOpen && (
              <div className="sidebar-submenu">
                <li><Link href="/admin/about"><FiInfo className="sidebar-icon" /> About Us</Link></li>
                <li><Link href="/admin/why-choose-us"><FiAward className="sidebar-icon" /> Why Choose Us</Link></li>
                <li><Link href="/admin/delivery-areas"><FiBox className="sidebar-icon" /> Delivery Areas</Link></li>
              </div>
            )}
            
            <li 
              className="sidebar-section clickable" 
              onClick={() => setSettingsOpen(!settingsOpen)}
            >
              Settings
              {settingsOpen ? <FiChevronDown className="section-icon" /> : <FiChevronRight className="section-icon" />}
            </li>
            {settingsOpen && (
              <div className="sidebar-submenu">
                <li><Link href="/admin/contact"><FiPhone className="sidebar-icon" /> Contact Info</Link></li>
                <li><Link href="/admin/whatsapp-settings"><FiMessageCircle className="sidebar-icon" /> WhatsApp Settings</Link></li>
                <li><Link href="/admin/seo-settings"><FiSearch className="sidebar-icon" /> SEO Settings</Link></li>
                <li><Link href="/admin/footer"><FiLayout className="sidebar-icon" /> Footer</Link></li>
              </div>
            )}
          </ul>
        </nav>
        
        <div className="sidebar-footer">
          <button onClick={() => { if(window.confirm('Are you sure you want to log out?')) logout(); }} className="logout-button">
            <FiLogOut style={{ marginRight: '8px', verticalAlign: 'middle' }} /> Log Out
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="admin-main">
        <header className="admin-header">
          <div className="admin-breadcrumb" style={{ display: 'flex', alignItems: 'center', fontSize: '18px', fontWeight: '700', color: 'var(--white)' }}>
            {pathnames.length === 0 ? (
              <span>Dashboard</span>
            ) : (
              pathnames.map((value, index) => {
                const to = `/${pathnames.slice(0, index + 1).join('/')}`;
                const isLast = index === pathnames.length - 1;
                const label = value.charAt(0).toUpperCase() + value.slice(1).replace(/-/g, ' ');

                return isLast ? (
                  <span key={to} style={{ color: 'var(--white)' }}>
                    {index > 0 && <span style={{ margin: '0 8px', color: 'var(--text-muted)', fontWeight: '400' }}>/</span>}
                    {label}
                  </span>
                ) : (
                  <React.Fragment key={to}>
                    {index > 0 && <span style={{ margin: '0 8px', color: 'var(--text-muted)', fontWeight: '400' }}>/</span>}
                    <Link href={to} style={{ color: 'var(--text-secondary)', textDecoration: 'none', transition: 'color 0.2s' }}>
                      {label}
                    </Link>
                  </React.Fragment>
                );
              })
            )}
          </div>
          <div className="admin-profile">
            <span>Admin User</span>
          </div>
        </header>
        
        <div className="admin-content">
          {children}
        </div>
      </main>
    </div>
  );
};

export default AdminLayout;
