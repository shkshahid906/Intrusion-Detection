"use client";

import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import Modal from '../../../../components/admin/Modal';
import '../AdminPages.css';

const Products = () => {
  const [products, setProducts] = useState([]);
  const [filteredProducts, setFilteredProducts] = useState([]);
  const [categories, setCategories] = useState([]);
  const [allFlavours, setAllFlavours] = useState([]);
  const [categoryFilter, setCategoryFilter] = useState('all');
  
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  
  const initialProductState = {
    id: null,
    name: '',
    slug: '',
    category_id: '',
    short_description: '',
    description: '',
    price: '',
    mrp: '',
    stock: '',
    sales_count: 0,
    nicotine_strength: '',
    featured: 0,
    status: 1,
    seo_title: '',
    seo_description: '',
    seo_keywords: '',
  };
  
  const [currentProduct, setCurrentProduct] = useState(initialProductState);
  const [selectedImages, setSelectedImages] = useState(null);
  const [selectedPrimaryImage, setSelectedPrimaryImage] = useState(null);

  const fetchData = async () => {
    try {
      const [prodRes, catRes, flavRes] = await Promise.all([
        api.get('/products'),
        api.get('/categories'),
        api.get('/flavours')
      ]);
      setProducts(prodRes.data.products || []);
      setFilteredProducts(prodRes.data.products || []);
      setCategories(catRes.data.categories || []);
      setAllFlavours(flavRes.data.flavours || []);
    } catch (error) {
      toast.error('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (categoryFilter === 'all') {
      setFilteredProducts(products);
    } else {
      setFilteredProducts(products.filter(p => p.category_id === parseInt(categoryFilter)));
    }
  }, [categoryFilter, products]);

  const openModal = async (product = null) => {
    if (product) {
      try {
        const res = await api.get(`/products/${product.slug || product.id}`);
        const fullProduct = res.data.product;
        
        setCurrentProduct(fullProduct);
        setIsEditing(true);
      } catch (err) {
        toast.error('Failed to load product details');
        return;
      }
    } else {
      setCurrentProduct(initialProductState);
      setIsEditing(false);
    }
    setSelectedImages(null);
    setSelectedPrimaryImage(null);
    setIsModalOpen(true);
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    if (name === 'name' && !isEditing) {
      const slug = value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
      setCurrentProduct(prev => ({ ...prev, [name]: value, slug }));
    } else {
      setCurrentProduct(prev => ({ ...prev, [name]: value }));
    }
  };

  const handlePrimaryFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedPrimaryImage(e.target.files[0]);
    }
  };

  const handleFileChange = (e) => {
    setSelectedImages(e.target.files);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    
    // Append standard fields
    Object.keys(currentProduct).forEach(key => {
      if (key !== 'images' && currentProduct[key] !== null) {
        formData.append(key, currentProduct[key]);
      }
    });

    // Append images
    if (selectedPrimaryImage) {
      formData.append('primary_image', selectedPrimaryImage);
    }
    
    if (selectedImages) {
      for (let i = 0; i < selectedImages.length; i++) {
        formData.append('images', selectedImages[i]);
      }
    }

    try {
      if (isEditing) {
        await api.put(`/products/${currentProduct.id}`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        toast.success('Product updated successfully');
      } else {
        await api.post('/products', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        toast.success('Product created successfully');
      }
      setIsModalOpen(false);
      fetchData();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Operation failed');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this product?')) {
      try {
        await api.delete(`/products/${id}`);
        toast.success('Product deleted');
        fetchData();
      } catch (error) {
        toast.error('Failed to delete product');
      }
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Products</h2>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <select 
            value={categoryFilter} 
            onChange={(e) => setCategoryFilter(e.target.value)}
            style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '12px' }}
          >
            <option value="all">All Categories</option>
            {categories.map(cat => (
              <option key={cat.id} value={cat.id}>{cat.category_name}</option>
            ))}
          </select>
          <button className="admin-btn-primary" onClick={() => openModal()} style={{ padding: '6px 12px', height: 'auto' }}>+ Add Product</button>
        </div>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Image</th>
              <th>Name</th>
              <th>Price</th>
              <th>Stock</th>
              <th>Nicotine (MG)</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredProducts.map((prod) => (
              <tr key={prod.id}>
                <td>
                  {prod.primary_image ? (
                    <img loading="lazy" 
                      src={`${prod.primary_image}`} 
                      alt={prod.name} 
                      style={{ width: '30px', height: '30px', objectFit: 'cover', borderRadius: '4px' }}
                    />
                  ) : (
                    <div style={{ width: '30px', height: '30px', background: 'var(--border-color)', borderRadius: '4px' }}></div>
                  )}
                </td>
                <td>{prod.name}</td>
                <td>₹{prod.price}</td>
                <td>{prod.stock}</td>
                <td>
                  {prod.nicotine_strength ? (
                    <span style={{ background: 'rgba(0, 184, 255, 0.15)', color: '#00B8FF', padding: '2px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: '600', border: '1px solid rgba(0, 184, 255, 0.3)' }}>
                      💧 {prod.nicotine_strength}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>-</span>
                  )}
                </td>
                <td>
                  <span className={`status-badge ${prod.status ? 'status-active' : 'status-inactive'}`}>
                    {prod.status ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="action-buttons">
                  <button className="admin-btn-edit" onClick={() => openModal(prod)}>Edit</button>
                  <button className="admin-btn-delete" onClick={() => handleDelete(prod.id)}>Delete</button>
                </td>
              </tr>
            ))}
            {filteredProducts.length === 0 && (
              <tr><td colSpan="7" style={{textAlign: 'center', padding: '20px'}}>No products found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)}
        title={isEditing ? 'Edit Product' : 'Add Product'}
      >
        <form className="admin-form" onSubmit={handleSubmit} style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '24px' }}>
          
          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Product Name</label>
            <input type="text" name="name" value={currentProduct.name || ''} onChange={handleInputChange} required />
          </div>
          
          <div className="form-group">
            <label>Slug</label>
            <input type="text" name="slug" value={currentProduct.slug || ''} onChange={handleInputChange} required />
          </div>

          <div className="form-group">
            <label>Category</label>
            <select name="category_id" value={currentProduct.category_id || ''} onChange={handleInputChange} required>
              <option value="">Select Category...</option>
              {categories.map(cat => (
                <option key={cat.id} value={cat.id}>{cat.category_name}</option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>Selling Price (₹)</label>
            <input type="number" step="0.01" name="price" value={currentProduct.price || ''} onChange={handleInputChange} required />
          </div>

          <div className="form-group">
            <label>MRP (Crossed Price ₹)</label>
            <input type="number" step="0.01" name="mrp" value={currentProduct.mrp || ''} onChange={handleInputChange} />
          </div>

          <div className="form-group">
            <label>Nicotine Strength (mg / %)</label>
            <input 
              type="text" 
              name="nicotine_strength" 
              value={currentProduct.nicotine_strength || ''} 
              onChange={handleInputChange} 
              placeholder="e.g. 5% mg, 50mg, 5%" 
            />
          </div>

          <div className="form-group">
            <label>Initial Stock</label>
            <input type="number" name="stock" value={currentProduct.stock || ''} onChange={handleInputChange} required />
          </div>

          <div className="form-group">
            <label>Sales Count (Popularity)</label>
            <input type="number" name="sales_count" value={currentProduct.sales_count || 0} onChange={handleInputChange} />
          </div>

          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Short Description</label>
            <textarea name="short_description" value={currentProduct.short_description || ''} onChange={handleInputChange} rows="2"></textarea>
          </div>

          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <label>Description (HTML allowed)</label>
            <textarea name="description" value={currentProduct.description || ''} onChange={handleInputChange} rows="4"></textarea>
          </div>

          <div className="form-group" style={{ gridColumn: '1 / -1' }}>
            <h4 style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', marginBottom: '15px' }}><i className="fas fa-images"></i> Media Gallery</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '30px' }}>
              
              {/* MAIN IMAGE COLUMN */}
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px', display: 'block' }}>Main Image</label>
                <div style={{ border: '2px dashed var(--border-color)', borderRadius: '12px', padding: '15px', textAlign: 'center', background: 'var(--bg-main)', height: '240px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', marginBottom: '15px' }}>
                  {selectedPrimaryImage ? (
                    <img loading="lazy" src={URL.createObjectURL(selectedPrimaryImage)} alt="New Main Preview" style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', borderRadius: '8px' }} />
                  ) : (isEditing && currentProduct.primary_image) ? (
                    <img loading="lazy" src={`${currentProduct.primary_image}`} alt="Current Main" style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', borderRadius: '8px' }} />
                  ) : (
                    <div style={{ color: 'var(--text-muted)' }}>
                      <i className="fas fa-image" style={{ fontSize: '48px', marginBottom: '10px' }}></i>
                      <p style={{ fontSize: '14px' }}>No main image set</p>
                    </div>
                  )}
                </div>
                <input type="file" name="primary_image" accept="image/*" onChange={handlePrimaryFileChange} style={{ width: '100%' }} />
                <small style={{color: 'var(--text-muted)', display: 'block', marginTop: '5px'}}>Used on homepage and product grids.</small>
              </div>

              {/* GALLERY CAROUSEL COLUMN */}
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px', display: 'block' }}>Gallery Carousel</label>
                <div style={{ display: 'flex', gap: '15px', flexWrap: 'wrap', minHeight: '120px', alignContent: 'flex-start', marginBottom: '15px' }}>
                  
                  {/* Existing Gallery Images */}
                  {isEditing && currentProduct.images && currentProduct.images.length > 0 && (
                    currentProduct.images.map((img, idx) => (
                      <div key={`exist-${idx}`} style={{ position: 'relative', width: '90px', height: '90px', border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden', background: 'var(--bg-card)', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}>
                        <img loading="lazy" src={`${img.image_path}`} alt="existing" style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
                        <button 
                          type="button" 
                          title="Delete Image"
                          onClick={async () => {
                            if (window.confirm("Delete this gallery image?")) {
                              try {
                                await api.delete(`/products/image/${img.id}`);
                                setCurrentProduct(prev => ({
                                  ...prev,
                                  images: prev.images.filter(i => i.id !== img.id)
                                }));
                                toast.success("Gallery image deleted");
                              } catch(err) {
                                toast.error("Failed to delete image");
                              }
                            }
                          }}
                          style={{ position: 'absolute', top: 4, right: 4, background: 'var(--error-red)', color: 'var(--bg-card)', border: 'none', borderRadius: '50%', width: '22px', height: '22px', cursor: 'pointer', fontSize: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 2px 4px rgba(0,0,0,0.2)' }}
                        >
                          &times;
                        </button>
                      </div>
                    ))
                  )}

                  {/* New Gallery File Previews */}
                  {selectedImages && Array.from(selectedImages).map((file, idx) => (
                    <div key={`new-${idx}`} style={{ position: 'relative', width: '90px', height: '90px', border: '2px solid var(--primary-accent)', borderRadius: '8px', overflow: 'hidden', background: 'var(--bg-card)' }}>
                      <img loading="lazy" src={URL.createObjectURL(file)} alt="new preview" style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
                      <span style={{ position: 'absolute', bottom: 0, width: '100%', background: 'var(--primary-accent)', color: 'var(--bg-card)', fontSize: '11px', textAlign: 'center', fontWeight: 'bold', padding: '2px 0' }}>NEW</span>
                    </div>
                  ))}
                  
                  {/* Empty state if no images at all */}
                  {!(isEditing && currentProduct.images && currentProduct.images.length > 0) && (!selectedImages || selectedImages.length === 0) && (
                    <div style={{ width: '100%', padding: '30px', textAlign: 'center', color: 'var(--text-muted)', border: '1px dashed var(--border-color)', borderRadius: '8px' }}>
                      No gallery images uploaded yet.
                    </div>
                  )}
                </div>

                <input type="file" name="images" multiple accept="image/*" onChange={handleFileChange} style={{ width: '100%' }} />
                <small style={{color: 'var(--text-muted)', display: 'block', marginTop: '5px'}}>Select multiple files. These appear as a swiper inside the product page.</small>
              </div>

            </div>
          </div>

          <div className="form-group">
            <label>Status</label>
            <select name="status" value={currentProduct.status} onChange={handleInputChange}>
              <option value={1}>Active</option>
              <option value={0}>Inactive</option>
            </select>
          </div>

          <div className="form-group">
            <label>Featured Product</label>
            <select name="featured" value={currentProduct.featured} onChange={handleInputChange}>
              <option value={1}>Yes</option>
              <option value={0}>No</option>
            </select>
          </div>

          <div className="form-actions" style={{ gridColumn: '1 / -1', marginTop: '12px' }}>
            <button type="button" className="btn-secondary" onClick={() => setIsModalOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary">Save Product</button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default Products;
