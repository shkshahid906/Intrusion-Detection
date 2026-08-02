"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import '../AdminPages.css';

const FooterSettings = () => {
  const [footerData, setFooterData] = useState({ footer_text: '', copyright_text: '', footer_logo_text: '' });
  const [loading, setLoading] = useState(true);

  const fetchFooter = async () => {
    try {
      const response = await api.get('/cms/footer');
      if (response.data.success && response.data.footer) {
        setFooterData({
          footer_text: response.data.footer.footer_text || '',
          copyright_text: response.data.footer.copyright_text || '',
          footer_logo_text: response.data.footer.footer_logo_text || ''
        });
      }
    } catch (error) {
      toast.error('Failed to load Footer Info');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFooter();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFooterData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.put('/cms/footer', footerData);
      toast.success('Footer updated successfully');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Manage Footer Text</h2>
      </div>

      <div className="admin-form-container" style={{ maxWidth: '1000px', padding: '24px', background: 'var(--bg-card)', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}>
        <form className="admin-form" onSubmit={handleSubmit} >
          
          {/* Left Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Footer Description Text</label>
              <textarea 
                name="footer_text" 
                value={footerData.footer_text} 
                onChange={handleInputChange} 
                style={{ flex: 1, minHeight: '120px', resize: 'vertical' }}
                placeholder="Brief description of your business shown in the footer"
              ></textarea>
            </div>
          </div>

          {/* Right Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="form-group" >
              <label>Copyright Text</label>
              <input 
                type="text" 
                name="copyright_text" 
                value={footerData.copyright_text} 
                onChange={handleInputChange} 
                placeholder="e.g. © 2024 Vapes Indiranagar. All rights reserved." 
              />
            </div>
            
            <div className="form-group" >
              <label>Footer Logo Text</label>
              <input 
                type="text" 
                name="footer_logo_text" 
                value={footerData.footer_logo_text} 
                onChange={handleInputChange} 
                placeholder="e.g. Vapeblr" 
              />
            </div>

            <div style={{ marginTop: 'auto', textAlign: 'right' }}>
              <button type="submit" className="btn-primary" style={{ padding: '12px 24px', fontSize: '16px', width: '100%' }}>Save Footer Settings</button>
            </div>
          </div>

        </form>
      </div>
    </div>
  );
};

export default FooterSettings;
