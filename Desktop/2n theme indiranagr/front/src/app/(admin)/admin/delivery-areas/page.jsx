"use client";

import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import Modal from '../../../../components/admin/Modal';
import '../AdminPages.css';

const DeliveryAreas = () => {
  const [areas, setAreas] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentArea, setCurrentArea] = useState({ 
    id: null, main_area: '', sub_areas: '', link_text: 'Vape delivery here', link_url: '/#products', display_order: 0, status: 'active' 
  });
  const [isEditing, setIsEditing] = useState(false);

  const fetchAreas = async () => {
    try {
      const response = await api.get('/cms/delivery-areas');
      if (response.data.success) {
        setAreas(response.data.areas);
      }
    } catch (error) {
      toast.error('Failed to load delivery areas');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAreas();
  }, []);

  const openModal = (area = null) => {
    if (area) {
      setCurrentArea(area);
      setIsEditing(true);
    } else {
      setCurrentArea({ id: null, main_area: '', sub_areas: '', link_text: 'Vape delivery here', link_url: '/#products', display_order: 0, status: 'active' });
      setIsEditing(false);
    }
    setIsModalOpen(true);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setCurrentArea(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      if (isEditing) {
        await api.put(`/cms/delivery-areas/${currentArea.id}`, currentArea);
        toast.success('Delivery area updated successfully');
      } else {
        await api.post('/cms/delivery-areas', currentArea);
        toast.success('Delivery area created successfully');
      }
      setIsModalOpen(false);
      fetchAreas();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this delivery area?')) {
      try {
        await api.delete(`/cms/delivery-areas/${id}`);
        toast.success('Delivery area deleted');
        fetchAreas();
      } catch (error) {
        toast.error('Failed to delete delivery area');
      }
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Delivery Areas</h2>
        <button className="admin-btn-primary" onClick={() => openModal()} style={{ padding: '6px 12px', height: 'auto' }}>+ Add Area</button>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Main Area</th>
              <th>Sub Areas</th>
              <th>Order</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {areas.map((area) => (
              <tr key={area.id}>
                <td>{area.main_area}</td>
                <td>{area.sub_areas.length > 50 ? area.sub_areas.substring(0, 50) + '...' : area.sub_areas}</td>
                <td>{area.display_order}</td>
                <td>
                  <span className={`status-badge ${area.status === 'active' ? 'status-active' : 'status-inactive'}`}>
                    {area.status === 'active' ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="action-buttons">
                  <button className="admin-btn-edit" onClick={() => openModal(area)}>Edit</button>
                  <button className="admin-btn-delete" onClick={() => handleDelete(area.id)}>Delete</button>
                </td>
              </tr>
            ))}
            {areas.length === 0 && (
              <tr><td colSpan="5" style={{textAlign: 'center'}}>No delivery areas found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title={isEditing ? 'Edit Delivery Area' : 'Add Delivery Area'}>
        <form className="admin-form" onSubmit={handleSubmit}>
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Main Area (e.g., BTM Layout)</label>
            <input type="text" name="main_area" value={currentArea.main_area || ''} onChange={handleInputChange} required />
          </div>
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Sub Areas (e.g., BTM 1st Stage, BTM 2nd Stage)</label>
            <textarea name="sub_areas" value={currentArea.sub_areas || ''} onChange={handleInputChange} rows="3" required></textarea>
          </div>
          <div className="form-group">
            <label>Link Text</label>
            <input type="text" name="link_text" value={currentArea.link_text || ''} onChange={handleInputChange} />
          </div>
          <div className="form-group">
            <label>Link URL</label>
            <input type="text" name="link_url" value={currentArea.link_url || ''} onChange={handleInputChange} />
          </div>
          <div className="form-group">
            <label>Display Order</label>
            <input type="number" name="display_order" value={currentArea.display_order} onChange={handleInputChange} />
          </div>
          <div className="form-group">
            <label>Status</label>
            <select name="status" value={currentArea.status} onChange={handleInputChange}>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
          <div className="form-actions" style={{ gridColumn: '1 / -1' }}>
            <button type="button" className="btn-secondary" onClick={() => setIsModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary">Save Delivery Area</button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default DeliveryAreas;
