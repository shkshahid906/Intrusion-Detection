"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import Modal from '../../../../components/admin/Modal';
import '../AdminPages.css';

const WhyChooseUs = () => {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentItem, setCurrentItem] = useState({ 
    id: null, title: '', description: '', icon: '', display_order: 0, status: 'active' 
  });
  const [isEditing, setIsEditing] = useState(false);

  const fetchItems = async () => {
    try {
      const response = await api.get('/cms/why-choose-us');
      if (response.data.success) {
        setItems(response.data.items);
      }
    } catch (error) {
      toast.error('Failed to load items');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const openModal = (item = null) => {
    if (item) {
      setCurrentItem(item);
      setIsEditing(true);
    } else {
      setCurrentItem({ id: null, title: '', description: '', icon: '', display_order: 0, status: 'active' });
      setIsEditing(false);
    }
    setIsModalOpen(true);
  };

  const handleToggleStatus = async (item) => {
    try {
      const newStatus = item.status === 'active' ? 'inactive' : 'active';
      const updatedItem = { ...item, status: newStatus };
      await api.put(`/cms/why-choose-us/${item.id}`, updatedItem);
      toast.success(`Feature marked as ${newStatus}`);
      fetchItems();
    } catch (error) {
      toast.error('Failed to update status');
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setCurrentItem(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      if (isEditing) {
        await api.put(`/cms/why-choose-us/${currentItem.id}`, currentItem);
        toast.success('Item updated successfully');
      } else {
        await api.post('/cms/why-choose-us', currentItem);
        toast.success('Item created successfully');
      }
      setIsModalOpen(false);
      fetchItems();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this feature?')) {
      try {
        await api.delete(`/cms/why-choose-us/${id}`);
        toast.success('Feature deleted');
        fetchItems();
      } catch (error) {
        toast.error('Failed to delete feature');
      }
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Why Choose Us Features</h2>
        <button className="admin-btn-primary" onClick={() => openModal()} style={{ padding: '6px 12px', height: 'auto' }}>+ Add Feature</button>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Icon</th>
              <th>Title</th>
              <th>Order</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td style={{ fontSize: '24px' }}>
                   {item.icon ? <i className={item.icon}></i> : '★'}
                </td>
                <td>{item.title}</td>
                <td>{item.display_order}</td>
                <td style={{ padding: '4px 8px', verticalAlign: 'middle' }}>
                  <label style={{ position: 'relative', display: 'inline-block', width: '34px', height: '20px', marginBottom: 0 }}>
                    <input 
                      type="checkbox" 
                      checked={item.status === 'active'} 
                      onChange={() => handleToggleStatus(item)}
                      style={{ opacity: 0, width: 0, height: 0 }}
                    />
                    <span style={{
                      position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0,
                      backgroundColor: item.status === 'active' ? 'var(--primary-accent)' : 'var(--text-secondary)',
                      transition: '.3s', borderRadius: '34px'
                    }}>
                      <span style={{
                        position: 'absolute', height: '14px', width: '14px', left: '3px', bottom: '3px',
                        backgroundColor: 'var(--bg-card)', transition: '.3s', borderRadius: '50%',
                        transform: item.status === 'active' ? 'translateX(14px)' : 'translateX(0)'
                      }} />
                    </span>
                  </label>
                </td>
                <td style={{ padding: '4px 8px' }}>
                  <div className="action-buttons" style={{ display: 'flex', gap: '8px' }}>
                    <button onClick={() => openModal(item)} style={{ padding: '4px', background: 'transparent', color: 'var(--primary-accent)', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center' }} title="Edit Feature">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                      </svg>
                    </button>
                    <button onClick={() => handleDelete(item.id)} style={{ padding: '4px', background: 'transparent', color: '#ff4757', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center' }} title="Delete Feature">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td colSpan="5" style={{textAlign: 'center'}}>No features found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title={isEditing ? 'Edit Feature' : 'Add Feature'}>
        <form className="admin-form" onSubmit={handleSubmit}>
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Title</label>
            <input type="text" name="title" value={currentItem.title || ''} onChange={handleInputChange} required />
          </div>
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Description</label>
            <textarea name="description" value={currentItem.description || ''} onChange={handleInputChange} rows="3" required></textarea>
          </div>
          <div className="form-group">
            <label>Icon Class (FontAwesome e.g., 'fas fa-truck')</label>
            <input type="text" name="icon" value={currentItem.icon || ''} onChange={handleInputChange} />
          </div>
          <div className="form-group">
            <label>Display Order</label>
            <input type="number" name="display_order" value={currentItem.display_order} onChange={handleInputChange} />
          </div>
          <div className="form-group">
            <label>Status</label>
            <select name="status" value={currentItem.status} onChange={handleInputChange}>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
          <div className="form-actions" style={{ gridColumn: '1 / -1' }}>
            <button type="button" className="btn-secondary" onClick={() => setIsModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary">Save Feature</button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default WhyChooseUs;
