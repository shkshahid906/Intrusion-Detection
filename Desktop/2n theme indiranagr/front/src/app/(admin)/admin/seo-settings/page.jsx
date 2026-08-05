"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import '../AdminPages.css';

const SEOSettings = () => {
  const [seoData, setSeoData] = useState({ 
    meta_title: '', meta_description: '', meta_keywords: '', canonical_url: '',
    og_title: '', og_description: '', twitter_title: '', twitter_description: '',
    robots_meta: '', google_analytics_id: '', google_tag_manager_id: '', meta_pixel_id: '', search_console_verification: ''
  });
  const [loading, setLoading] = useState(true);

  const fetchSEO = async () => {
    try {
      const response = await api.get('/seo/settings');
      if (response.data.success && response.data.seo) {
        const info = response.data.seo;
        const cleanInfo = {};
        Object.keys(info).forEach(key => {
            cleanInfo[key] = info[key] || '';
        });
        setSeoData(cleanInfo);
      }
    } catch (error) {
      toast.error('Failed to load SEO settings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSEO();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setSeoData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.put('/seo/settings', seoData);
      toast.success('SEO Settings updated successfully');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Global SEO & Tracking Settings</h2>
      </div>

      <div className="admin-form-container" style={{ maxWidth: '1000px', padding: '24px', background: 'var(--bg-card)', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}>
        <form className="admin-form" onSubmit={handleSubmit} >
          
          {/* Left Column: Meta Tags */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <h3 style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>Global Meta Tags</h3>
            
            <div className="form-group" >
              <label>Meta Title (Default)</label>
              <input type="text" name="meta_title" value={seoData.meta_title} onChange={handleInputChange} placeholder="e.g. Vape Shop Indiranagar | Premium Vapes" />
            </div>

            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Meta Description</label>
              <textarea name="meta_description" value={seoData.meta_description} onChange={handleInputChange} placeholder="e.g. Shop the best premium vapes in Indiranagar with same-day delivery." style={{ flex: 1, minHeight: '100px', resize: 'vertical' }}></textarea>
            </div>

            <div className="form-group" >
              <label>Meta Keywords</label>
              <textarea name="meta_keywords" value={seoData.meta_keywords} onChange={handleInputChange} rows="2" placeholder="e.g. vapes, indiranagar, e-cigarettes, vape shop bangalore" style={{ resize: 'vertical' }}></textarea>
            </div>
          </div>

          {/* Right Column: Tracking */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <h3 style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>Tracking & Analytics</h3>

            <div className="form-group" >
              <label>Google Analytics ID</label>
              <input type="text" name="google_analytics_id" value={seoData.google_analytics_id} onChange={handleInputChange} placeholder="e.g. G-XXXXXXXXXX" />
            </div>

            <div className="form-group" >
              <label>Meta (Facebook) Pixel ID</label>
              <input type="text" name="meta_pixel_id" value={seoData.meta_pixel_id} onChange={handleInputChange} placeholder="e.g. 123456789012345" />
            </div>
            
            <div className="form-group" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label>Google Search Console Verification HTML</label>
              <textarea name="search_console_verification" value={seoData.search_console_verification} onChange={handleInputChange} placeholder="e.g. abc123def456ghi789 (Just the code, not the full HTML tag)" style={{ flex: 1, minHeight: '100px', resize: 'vertical' }}></textarea>
            </div>

            <div style={{ marginTop: 'auto', textAlign: 'right' }}>
              <button type="submit" className="btn-primary" style={{ padding: '12px 24px', fontSize: '16px', width: '100%' }}>Save SEO Settings</button>
            </div>
          </div>

        </form>
      </div>
    </div>
  );
};

export default SEOSettings;
