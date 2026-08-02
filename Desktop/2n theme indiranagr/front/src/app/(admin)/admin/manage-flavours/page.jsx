"use client";

import React, { useState, useEffect, useMemo } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import '../AdminPages.css';

const ManageFlavours = () => {
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [flavours, setFlavours] = useState([]); // Array of { flavour_name, stock }
  
  const [searchQuery, setSearchQuery] = useState('');
  const [sortOrder, setSortOrder] = useState('az');

  const fetchProducts = async () => {
    try {
      const response = await api.get('/products');
      if (response.data.success) {
        setProducts(response.data.products);
      }
    } catch (error) {
      toast.error('Failed to load products');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProducts();
  }, []);

  const selectProductForFlavours = async (product) => {
    setSelectedProduct(product);
    try {
      const response = await api.get(`/products/${product.id}/flavours`);
      if (response.data.success) {
        setFlavours(response.data.flavours);
      }
    } catch (error) {
      toast.error('Failed to load flavours for this product');
      setFlavours([]);
    }
  };

  const handleAddRow = () => {
    setFlavours([...flavours, { flavour_name: '', stock: 0 }]);
  };

  const handleRemoveRow = (index) => {
    const newFlavours = [...flavours];
    newFlavours.splice(index, 1);
    setFlavours(newFlavours);
  };

  const handleFlavourChange = (index, field, value) => {
    const newFlavours = [...flavours];
    newFlavours[index][field] = value;
    setFlavours(newFlavours);
  };

  const handleSaveFlavours = async (e) => {
    e.preventDefault();
    if (flavours.some(f => !f.flavour_name.trim())) {
      toast.error('Flavour names cannot be empty');
      return;
    }

    try {
      await api.put(`/products/${selectedProduct.id}/flavours`, { flavours });
      toast.success('Flavours updated successfully');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to save flavours');
    }
  };

  const filteredAndSortedProducts = useMemo(() => {
    let filtered = products.filter(p => 
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (p.sku && p.sku.toLowerCase().includes(searchQuery.toLowerCase()))
    );

    if (sortOrder === 'az') {
      filtered.sort((a, b) => a.name.localeCompare(b.name));
    } else if (sortOrder === 'za') {
      filtered.sort((a, b) => b.name.localeCompare(a.name));
    }

    return filtered;
  }, [products, searchQuery, sortOrder]);

  if (loading) return <div style={{ padding: '20px', color: 'var(--text-secondary)' }}>Loading...</div>;

  return (
    <div className="admin-page" style={{ padding: '10px 16px', boxSizing: 'border-box', height: 'calc(100vh - 64px)', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-main)', border: 'none', boxShadow: 'none' }}>
      
      <div className="admin-page-header" style={{ background: 'transparent', padding: '0 0 10px 0', border: 'none' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--white)' }}>Inventory & Flavours</h2>
      </div>

      <div style={{ display: 'flex', gap: '12px', flex: 1, overflow: 'hidden' }}>
        
        {/* Left Panel: Catalog Selector */}
        <div style={{ width: '300px', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0, boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)' }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <i className="fas fa-layer-group"></i> Catalog Selector
            </h3>
            
            <input 
              type="text" 
              placeholder="Search by name or SKU..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--bg-main)', color: 'var(--white)', marginBottom: '8px', fontSize: '13px', outline: 'none' }}
            />
            
            <select 
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value)}
              style={{ width: '100%', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--bg-main)', color: 'var(--white)', fontSize: '13px', outline: 'none', cursor: 'pointer' }}
            >
              <option style={{ background: 'var(--bg-card)', color: 'var(--white)' }} value="az">Alphabetical (A-Z)</option>
              <option style={{ background: 'var(--bg-card)', color: 'var(--white)' }} value="za">Alphabetical (Z-A)</option>
            </select>
          </div>

          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filteredAndSortedProducts.map(prod => (
              <div 
                key={prod.id} 
                onClick={() => selectProductForFlavours(prod)}
                style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '10px', 
                  padding: '10px 14px', 
                  borderBottom: '1px solid var(--border-color)',
                  cursor: 'pointer',
                  background: selectedProduct?.id === prod.id ? 'var(--bg-secondary)' : 'var(--bg-card)',
                  borderLeft: selectedProduct?.id === prod.id ? '4px solid var(--primary-accent)' : '4px solid transparent',
                  transition: 'background 0.2s'
                }}
                onMouseOver={(e) => { if(selectedProduct?.id !== prod.id) e.currentTarget.style.background = 'var(--bg-main)' }}
                onMouseOut={(e) => { if(selectedProduct?.id !== prod.id) e.currentTarget.style.background = 'var(--bg-card)' }}
              >
                {prod.primary_image ? (
                  <img loading="lazy" src={`${prod.primary_image}`} alt={prod.name} style={{ width: '40px', height: '40px', objectFit: 'cover', borderRadius: '6px', border: '1px solid var(--border-color)' }} />
                ) : (
                  <div style={{ width: '40px', height: '40px', background: 'var(--border-color)', borderRadius: '6px' }}></div>
                )}
                <div>
                  <h4 style={{ margin: '0 0 2px 0', fontSize: '13px', color: selectedProduct?.id === prod.id ? 'var(--primary-accent)' : 'var(--text-main)', fontWeight: '600', lineBreak: 'anywhere' }}>{prod.name}</h4>
                  <p style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{prod.category_name || 'Uncategorized'}</p>
                </div>
              </div>
            ))}
            {filteredAndSortedProducts.length === 0 && (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                No products found matching your search.
              </div>
            )}
          </div>
        </div>

        {/* Right Panel: Editor or Empty State */}
        <div style={{ flex: 1, background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)' }}>
          {!selectedProduct ? (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
              <div style={{ width: '60px', height: '60px', background: 'var(--bg-main)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                <i className="fas fa-hand-pointer" style={{ fontSize: '24px', color: 'var(--success-green)' }}></i>
              </div>
              <h2 style={{ fontSize: '18px', color: 'var(--white)', fontWeight: '700', marginBottom: '8px' }}>Select a Product</h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '13px', textAlign: 'center', maxWidth: '280px' }}>
                Choose a product from the left catalog to manage its flavour varieties and stock levels.
              </p>
            </div>
          ) : (
            <form className="admin-form" onSubmit={handleSaveFlavours} style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden', padding: 0 }}>
              
              {/* Right Panel Header */}
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: '12px', background: 'var(--bg-card)', flexShrink: 0 }}>
                {selectedProduct.primary_image ? (
                  <img loading="lazy" src={`${selectedProduct.primary_image}`} alt="Product" style={{ width: '48px', height: '48px', borderRadius: '6px', objectFit: 'cover' }} />
                ) : (
                  <div style={{ width: '48px', height: '48px', background: 'var(--border-color)', borderRadius: '6px' }}></div>
                )}
                <div>
                  <h2 style={{ margin: '0 0 2px 0', fontSize: '18px', color: 'var(--white)', fontWeight: '700' }}>{selectedProduct.name}</h2>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>Manage inventory per flavour</p>
                </div>
              </div>

              {/* Scrollable Flavours List */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '12px', background: 'var(--bg-main)' }}>
                <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)', minHeight: '100%', boxSizing: 'border-box' }}>
                  
                  <div style={{ marginBottom: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '12px', margin: 0 }}>Add individual flavour variations and their specific stock counts.</p>
                    <button type="button" className="admin-btn-primary" onClick={handleAddRow} style={{ flexShrink: 0 }}>
                      + Add Flavour Row
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {flavours.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '24px', background: 'var(--bg-main)', borderRadius: '8px', border: '1px dashed var(--border-color)' }}>
                        <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: 0 }}>No flavours configured. Click "+ Add Flavour Row" to start.</p>
                      </div>
                    ) : (
                      flavours.map((flavour, index) => (
                        <div key={index} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start', background: 'var(--bg-main)', padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                          <div style={{ flex: 2 }}>
                            <label style={{ display: index === 0 ? 'block' : 'none', fontSize: '10px', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '4px', textTransform: 'uppercase' }}>Flavour Name</label>
                            <input 
                              type="text" 
                              placeholder="e.g. Mango Ice"
                              value={flavour.flavour_name} 
                              onChange={(e) => handleFlavourChange(index, 'flavour_name', e.target.value)} 
                              required 
                              style={{ width: '100%', padding: '6px 10px', border: '1px solid var(--border-color)', background: 'var(--bg-secondary)', color: 'var(--white)', borderRadius: '6px', fontSize: '13px', outline: 'none' }}
                              onFocus={(e) => e.target.style.borderColor = 'var(--primary-accent)'}
                              onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                            />
                          </div>
                          <div style={{ flex: 1 }}>
                            <label style={{ display: index === 0 ? 'block' : 'none', fontSize: '10px', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '4px', textTransform: 'uppercase' }}>Stock Qty</label>
                            <input 
                              type="number" 
                              value={flavour.stock} 
                              onChange={(e) => handleFlavourChange(index, 'stock', parseInt(e.target.value) || 0)} 
                              required 
                              style={{ width: '100%', padding: '6px 10px', border: '1px solid var(--border-color)', background: 'var(--bg-secondary)', color: 'var(--white)', borderRadius: '6px', fontSize: '13px', outline: 'none' }}
                              onFocus={(e) => e.target.style.borderColor = 'var(--primary-accent)'}
                              onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                            />
                          </div>
                          <div style={{ paddingTop: index === 0 ? '18px' : '0' }}>
                            <button 
                              type="button" 
                              onClick={() => handleRemoveRow(index)} 
                              style={{ padding: '6px 10px', background: 'rgba(229, 57, 53, 0.1)', color: 'var(--error-red)', border: '1px solid rgba(229, 57, 53, 0.2)', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', height: '31px' }}
                              title="Remove Row"
                            >
                              ✕
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Fixed Footer for Save Button */}
              <div style={{ padding: '12px 16px', background: 'var(--bg-card)', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'flex-end', flexShrink: 0 }}>
                <button type="submit" className="admin-btn-primary" style={{ padding: '6px 16px !important', fontSize: '12px !important', borderRadius: '6px' }}>Save Flavour Changes</button>
              </div>
            </form>
          )}
        </div>

      </div>
    </div>
  );
};

export default ManageFlavours;
