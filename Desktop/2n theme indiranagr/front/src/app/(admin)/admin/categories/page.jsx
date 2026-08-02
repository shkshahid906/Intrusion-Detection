"use client";

﻿import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import Modal from '../../../../components/admin/Modal';
import '../AdminPages.css';

const Categories = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentCategory, setCurrentCategory] = useState({ id: null, category_name: '', slug: '', description: '', status: 1 });
  const [isEditing, setIsEditing] = useState(false);

  const fetchCategories = async () => {
    try {
      const response = await api.get('/categories');
      if (response.data.success) {
        setCategories(response.data.categories);
      }
    } catch (error) {
      toast.error('Failed to load categories');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  const openModal = (category = null) => {
    if (category) {
      setCurrentCategory(category);
      setIsEditing(true);
    } else {
      setCurrentCategory({ id: null, category_name: '', slug: '', description: '', status: 1 });
      setIsEditing(false);
    }
    setIsModalOpen(true);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    // Auto-generate slug if typing in name
    if (name === 'category_name' && !isEditing) {
      const slug = value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
      setCurrentCategory(prev => ({ ...prev, [name]: value, slug }));
    } else {
      setCurrentCategory(prev => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (isEditing) {
        await api.put(`/categories/${currentCategory.id}`, currentCategory);
        toast.success('Category updated successfully');
      } else {
        await api.post('/categories', currentCategory);
        toast.success('Category created successfully');
      }
      setIsModalOpen(false);
      fetchCategories();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this category?')) {
      try {
        await api.delete(`/categories/${id}`);
        toast.success('Category deleted');
        fetchCategories();
      } catch (error) {
        toast.error('Failed to delete category');
      }
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Categories</h2>
        <button className="admin-btn-primary" onClick={() => openModal()} style={{ padding: '6px 12px', height: 'auto' }}>+ Add Category</button>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Slug</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {categories.map((cat) => (
              <tr key={cat.id}>
                <td>{cat.id}</td>
                <td>{cat.category_name}</td>
                <td>{cat.slug}</td>
                <td>
                  <span className={`status-badge ${cat.status ? 'status-active' : 'status-inactive'}`}>
                    {cat.status ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="action-buttons">
                  <button className="admin-btn-edit" onClick={() => openModal(cat)}>Edit</button>
                  <button className="admin-btn-delete" onClick={() => handleDelete(cat.id)}>Delete</button>
                </td>
              </tr>
            ))}
            {categories.length === 0 && (
              <tr><td colSpan="5" style={{textAlign: 'center'}}>No categories found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)}
        title={isEditing ? 'Edit Category' : 'Add Category'}
      >
        <form className="admin-form" onSubmit={handleSubmit} >
          <div className="form-group">
            <label>Category Name</label>
            <input type="text" name="category_name" value={currentCategory.category_name} onChange={handleInputChange} required />
          </div>
          <div className="form-group">
            <label>Slug</label>
            <input type="text" name="slug" value={currentCategory.slug} onChange={handleInputChange} required />
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea name="description" value={currentCategory.description} onChange={handleInputChange} rows="3"></textarea>
          </div>
          <div className="form-group">
            <label>Status</label>
            <select name="status" value={currentCategory.status} onChange={handleInputChange}>
              <option value={1}>Active</option>
              <option value={0}>Inactive</option>
            </select>
          </div>
          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={() => setIsModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary">Save Category</button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default Categories;
