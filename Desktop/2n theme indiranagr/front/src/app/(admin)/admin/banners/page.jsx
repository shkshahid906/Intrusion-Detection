"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import Modal from '../../../../components/admin/Modal';
import '../AdminPages.css';

const Banners = () => {
  const [banners, setBanners] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentBanner, setCurrentBanner] = useState({ 
    id: null, title: '', subtitle: '', button_text: '', button_link: '', display_order: 0, status: 'active' 
  });
  const [isEditing, setIsEditing] = useState(false);
  const [selectedImage, setSelectedImage] = useState(null);

  const fetchBanners = async () => {
    try {
      const response = await api.get('/banners');
      if (response.data.success) {
        setBanners(response.data.banners);
      }
    } catch (error) {
      toast.error('Failed to load banners');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBanners();
  }, []);

  const openModal = () => {
    setCurrentBanner({ id: null, title: '', subtitle: '', button_text: '', button_link: '', display_order: 0, status: 'active' });
    setIsEditing(false);
    setSelectedImage(null);
    setIsModalOpen(true);
  };

  const handleToggleStatus = async (banner) => {
    try {
      const newStatus = banner.status === 'active' ? 'inactive' : 'active';
      const formData = new FormData();
      formData.append('status', newStatus);
      
      await api.put(`/banners/${banner.id}`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      toast.success(`Banner marked as ${newStatus}`);
      fetchBanners();
    } catch (error) {
      toast.error('Failed to update status');
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setCurrentBanner(prev => ({ ...prev, [name]: value }));
  };

  const handleFileChange = (e) => {
    setSelectedImage(e.target.files[0]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    
    Object.keys(currentBanner).forEach(key => {
      if (currentBanner[key] !== null) {
        formData.append(key, currentBanner[key]);
      }
    });

    if (selectedImage) {
      formData.append('image', selectedImage);
    }

    try {
      if (isEditing) {
        await api.put(`/banners/${currentBanner.id}`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
        toast.success('Banner updated successfully');
      } else {
        await api.post('/banners', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
        toast.success('Banner created successfully');
      }
      setIsModalOpen(false);
      fetchBanners();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this banner?')) {
      try {
        await api.delete(`/banners/${id}`);
        toast.success('Banner deleted');
        fetchBanners();
      } catch (error) {
        toast.error('Failed to delete banner');
      }
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Home Hero Banners</h2>
        <button className="admin-btn-primary" onClick={() => openModal()} style={{ padding: '6px 12px', height: 'auto' }}>+ Add Banner</button>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Image</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {banners.map((banner) => (
              <tr key={banner.id}>
                <td style={{ padding: '4px 8px' }}>
                  {banner.image_path ? (
                    <img loading="lazy" src={`${banner.image_path}`} alt="Banner" style={{ width: '180px', height: '70px', objectFit: 'cover', borderRadius: '6px', display: 'block' }} />
                  ) : 'No Image'}
                </td>
                <td style={{ padding: '4px 8px', verticalAlign: 'middle' }}>
                  <label style={{ position: 'relative', display: 'inline-block', width: '34px', height: '20px', marginBottom: 0 }}>
                    <input 
                      type="checkbox" 
                      checked={banner.status === 'active'} 
                      onChange={() => handleToggleStatus(banner)}
                      style={{ opacity: 0, width: 0, height: 0 }}
                    />
                    <span style={{
                      position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
                      backgroundColor: banner.status === 'active' ? 'var(--primary-accent)' : 'var(--text-secondary)',
                      transition: '.3s', borderRadius: '34px'
                    }}>
                      <span style={{
                        position: 'absolute', height: '14px', width: '14px', left: '3px', bottom: '3px',
                        backgroundColor: 'var(--bg-card)', transition: '.3s', borderRadius: '50%',
                        transform: banner.status === 'active' ? 'translateX(14px)' : 'translateX(0)'
                      }} />
                    </span>
                  </label>
                </td>
                <td style={{ padding: '4px 8px' }}>
                  <div className="action-buttons" style={{ display: 'flex', gap: '8px' }}>
                    <button onClick={() => handleDelete(banner.id)} style={{ padding: '4px', background: 'transparent', color: '#ff4757', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center' }} title="Delete Banner">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {banners.length === 0 && (
              <tr><td colSpan="5" style={{textAlign: 'center'}}>No banners found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="Add Banner">
        <form className="admin-form" onSubmit={handleSubmit}>
          
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Status</label>
            <select name="status" value={currentBanner.status} onChange={handleInputChange}>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Banner Image</label>
            <input type="file" name="image" accept="image/*" onChange={handleFileChange} />
            <div style={{ display: 'flex', gap: '10px', marginTop: '10px', flexWrap: 'wrap' }}>
              {selectedImage && (
                <div style={{ position: 'relative', width: '160px', height: '80px', border: '2px solid var(--primary-accent)', borderRadius: '4px', overflow: 'hidden' }}>
                  <img loading="lazy" src={URL.createObjectURL(selectedImage)} alt="new preview" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                  <span style={{ position: 'absolute', bottom: 0, width: '100%', background: 'var(--primary-accent)', color: 'var(--bg-card)', fontSize: '10px', textAlign: 'center' }}>Preview</span>
                </div>
              )}
            </div>
          </div>
          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={() => setIsModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary">Save Banner</button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default Banners;
