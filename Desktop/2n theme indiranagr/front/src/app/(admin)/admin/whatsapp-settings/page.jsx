"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import '../AdminPages.css';

const WhatsAppSettings = () => {
  const [waData, setWaData] = useState({ display_number: '', default_message: '', custom_template: '' });
  const [loading, setLoading] = useState(true);

  const fetchWa = async () => {
    try {
      const response = await api.get('/cms/whatsapp');
      if (response.data.success && response.data.whatsapp) {
        const info = response.data.whatsapp;
        setWaData({
          display_number: info.display_number || '',
          default_message: info.default_message || '',
          custom_template: info.custom_template || ''
        });
      }
    } catch (error) {
      toast.error('Failed to load WhatsApp settings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWa();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    
    setWaData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.put('/cms/whatsapp', waData);
      toast.success('WhatsApp Settings updated');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>WhatsApp Integration Settings</h2>
      </div>

      <div className="admin-form-container" style={{ maxWidth: '1000px', padding: '24px', background: 'var(--bg-card)', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.5)' }}>
        <form className="admin-form" onSubmit={handleSubmit} >
          
          {/* Left Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="form-group" >
              <label>Business WhatsApp Number</label>
              <input 
                type="text" 
                name="display_number" 
                value={waData.display_number} 
                readOnly
                placeholder="Set this in Contact Info"
              />
              <small style={{ color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>Managed from Settings &gt; Contact Info. The same number is used for every WhatsApp link.</small>
            </div>

            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Default Message (Floating Button)</label>
              <textarea 
                name="default_message" 
                value={waData.default_message} 
                onChange={handleInputChange} 
                style={{ flex: 1, minHeight: '120px', resize: 'vertical' }}
              ></textarea>
            </div>
          </div>

          {/* Right Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Order Checkout Template</label>
              <textarea 
                name="custom_template" 
                value={waData.custom_template} 
                onChange={handleInputChange} 
                style={{ flex: 1, minHeight: '150px', resize: 'vertical' }}
              ></textarea>
              <small style={{ color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>Use placeholders: [CUSTOMER_NAME], [ORDER_ID], [ITEMS], [TOTAL]</small>
            </div>

            <div style={{ marginTop: 'auto', textAlign: 'right' }}>
              <button type="submit" className="btn-primary" style={{ padding: '12px 24px', fontSize: '16px', width: '100%' }}>Save WhatsApp Settings</button>
            </div>
          </div>

        </form>
      </div>
    </div>
  );
};

export default WhatsAppSettings;
