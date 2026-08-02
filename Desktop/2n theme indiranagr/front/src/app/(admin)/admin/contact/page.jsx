"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import logoImg from '../../../../assets/v_h_logo.jpeg';
import '../AdminPages.css';

const Contact = () => {
  const [contactData, setContactData] = useState({ 
    phone: '', email: '', logo_image: '',
    address: '', google_map_link: '', facebook: '', instagram: '', twitter: '', youtube: '' 
  });
  const [loading, setLoading] = useState(true);
  const [selectedLogo, setSelectedLogo] = useState(null);

  const fetchContact = async () => {
    try {
      const response = await api.get('/cms/contact-info');
      if (response.data.success && response.data.contactInfo) {
        // Filter out null values
        const info = response.data.contactInfo;
        const cleanInfo = {};
        Object.keys(info).forEach(key => {
            cleanInfo[key] = info[key] || '';
        });
        setContactData(cleanInfo);
      }
    } catch (error) {
      toast.error('Failed to load Contact Info');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchContact();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    
    if (name === 'phone') {
      const numericValue = value.replace(/\D/g, '');
      if (numericValue.length <= 10) {
        setContactData(prev => ({ ...prev, [name]: numericValue }));
      }
      return;
    }

    setContactData(prev => ({ ...prev, [name]: value }));
  };

  const handleLogoChange = (e) => {
    setSelectedLogo(e.target.files[0] || null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    [
      'phone',
      'email',
      'address',
      'google_map_link',
      'facebook',
      'instagram',
      'twitter',
      'youtube',
      'logo_image'
    ].forEach((key) => {
      formData.append(key, contactData[key] || '');
    });

    if (selectedLogo) {
      formData.append('logo_image', selectedLogo);
    }

    try {
      await api.put('/cms/contact-info', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      toast.success('Contact Information updated successfully');
      setSelectedLogo(null);
      fetchContact();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Manage Contact Information</h2>
      </div>

      <div className="admin-form-container" style={{ maxWidth: '1000px', padding: '5px', background: 'var(--bg-card)', borderRadius: '8px' }}>
        <form className="admin-form" onSubmit={handleSubmit} >
          
          {/* Left Column: Basic Contact Info */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <h3 style={{ paddingBottom: '10px', borderBottom: '1px solid var(--border-color)' }}>Basic Information</h3>
            
            <div className="form-group" >
              <label>Header Logo</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
                <div style={{ width: '120px', minHeight: '62px', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-main)' }}>
                  <img
                    loading="lazy"
                    src={selectedLogo ? URL.createObjectURL(selectedLogo) : (contactData.logo_image || logoImg.src)}
                    alt="Header logo preview"
                    style={{ maxWidth: '100%', maxHeight: '46px', objectFit: 'contain' }}
                  />
                </div>
                <input type="file" name="logo_image" accept="image/*" onChange={handleLogoChange} />
              </div>
              <small style={{ color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>This logo appears in the website header.</small>
            </div>

            <div className="form-group" >
              <label>Phone Number</label>
              <input type="text" name="phone" value={contactData.phone} onChange={handleInputChange} maxLength="10" pattern="[0-9]{10}" title="Please enter exactly 10 digits" />
              <small style={{ color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>This number is used for phone support and every WhatsApp link.</small>
            </div>

            <div className="form-group" >
              <label>Email Address</label>
              <input type="email" name="email" value={contactData.email} onChange={handleInputChange} />
            </div>

            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Physical Address</label>
              <textarea name="address" value={contactData.address} onChange={handleInputChange} style={{ flex: 1, minHeight: '80px', resize: 'vertical' }}></textarea>
            </div>
          </div>

          {/* Right Column: Maps & Socials */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <h3 style={{ paddingBottom: '10px', borderBottom: '1px solid var(--border-color)' }}>Maps & Social Links</h3>
            
            <div className="form-group" >
              <label>Google Maps Embed Link</label>
              <textarea name="google_map_link" value={contactData.google_map_link} onChange={handleInputChange} rows="2" style={{ resize: 'vertical' }}></textarea>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
              <div className="form-group" >
                <label>Instagram URL</label>
                <input type="text" name="instagram" value={contactData.instagram} onChange={handleInputChange} />
              </div>
              <div className="form-group" >
                <label>Facebook URL</label>
                <input type="text" name="facebook" value={contactData.facebook} onChange={handleInputChange} />
              </div>
              <div className="form-group" >
                <label>Twitter URL</label>
                <input type="text" name="twitter" value={contactData.twitter} onChange={handleInputChange} />
              </div>
              <div className="form-group" >
                <label>YouTube URL</label>
                <input type="text" name="youtube" value={contactData.youtube} onChange={handleInputChange} />
              </div>
            </div>

            <div style={{ marginTop: 'auto', textAlign: 'right' }}>
              <button type="submit" className="btn-primary" style={{ padding: '12px 24px', fontSize: '16px', width: '100%' }}>Save Contact Info</button>
            </div>
          </div>
          
        </form>
      </div>
    </div>
  );
};

export default Contact;
