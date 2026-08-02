"use client";

import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import '../AdminPages.css';

const Enquiries = () => {
  const [enquiries, setEnquiries] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchEnquiries = async () => {
    try {
      const response = await api.get('/enquiries');
      if (response.data.success) {
        setEnquiries(response.data.enquiries);
      }
    } catch (error) {
      toast.error('Failed to load enquiries');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEnquiries();
  }, []);

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this enquiry?')) {
      try {
        await api.delete(`/enquiries/${id}`);
        toast.success('Enquiry deleted');
        fetchEnquiries();
      } catch (error) {
        toast.error('Failed to delete enquiry');
      }
    }
  };

  const handleDeleteOldEnquiries = async () => {
    if (!window.confirm('Are you sure you want to delete all enquiries older than 30 days? This action cannot be undone.')) return;
    try {
      const response = await api.delete('/enquiries/bulk/old');
      toast.success(response.data.message || 'Old enquiries deleted');
      fetchEnquiries();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to delete old enquiries');
    }
  };

  const handleDeleteAllEnquiries = async () => {
    if (!window.confirm('WARNING: Are you sure you want to delete ALL enquiries? This action CANNOT be undone!')) return;
    try {
      const response = await api.delete('/enquiries/bulk/all');
      toast.success(response.data.message || 'All enquiries deleted');
      fetchEnquiries();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to delete all enquiries');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Customer Enquiries</h2>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="admin-btn-delete" onClick={handleDeleteOldEnquiries}>Delete &gt; 30 Days</button>
          <button className="admin-btn-delete" onClick={handleDeleteAllEnquiries}>Delete All</button>
        </div>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Name</th>
              <th>Phone</th>
              <th>Email</th>
              <th>Message</th>
              <th>Source</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {enquiries.map((enq) => (
              <tr key={enq.id}>
                <td>{new Date(enq.created_at).toLocaleDateString()}</td>
                <td>{enq.name}</td>
                <td>{enq.phone || enq.mobile}</td>
                <td>{enq.email || '-'}</td>
                <td style={{ maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={enq.message}>
                  {enq.message}
                </td>
                <td>
                  {enq.enquiry_type ? (
                    <span className={`status-badge ${enq.enquiry_type === 'whatsapp' ? 'status-active' : ''}`} style={enq.enquiry_type === 'contact_form' ? {background: 'var(--border-color)', color: 'var(--white)'} : {}}>
                      {enq.enquiry_type}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
                <td className="action-buttons">
                  <a href={`https://wa.me/${((enq.phone || enq.mobile || '').replace(/\D/g, '')).length === 10 ? `91${(enq.phone || enq.mobile || '').replace(/\D/g, '')}` : (enq.phone || enq.mobile || '').replace(/\D/g, '')}`} target="_blank" rel="noreferrer" className="admin-btn-whatsapp" style={{ textDecoration: 'none' }}>WhatsApp</a>
                  {enq.email && (
                    <a href={`mailto:${enq.email}`} target="_blank" rel="noreferrer" className="admin-btn-edit" style={{ textDecoration: 'none' }}>Email</a>
                  )}
                  <button className="admin-btn-delete" onClick={() => handleDelete(enq.id)}>Delete</button>
                </td>
              </tr>
            ))}
            {enquiries.length === 0 && (
              <tr><td colSpan="7" style={{textAlign: 'center'}}>No enquiries found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Enquiries;
