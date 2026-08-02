"use client";

import React, { useState, useEffect } from 'react';
import api from '../../../../services/api';
import { toast } from 'react-toastify';
import Modal from '../../../../components/admin/Modal';
import '../AdminPages.css';

const Orders = () => {
  const [orders, setOrders] = useState([]);
  const [filteredOrders, setFilteredOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [orderDetails, setOrderDetails] = useState([]);
  const [statusFilter, setStatusFilter] = useState('all');

  const fetchOrders = async () => {
    try {
      const response = await api.get('/orders');
      if (response.data.success) {
        setOrders(response.data.orders);
        setFilteredOrders(response.data.orders);
      }
    } catch (error) {
      toast.error('Failed to load orders');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrders();
  }, []);

  useEffect(() => {
    if (statusFilter === 'all') {
      setFilteredOrders(orders);
    } else {
      setFilteredOrders(orders.filter(o => o.order_status === statusFilter));
    }
  }, [statusFilter, orders]);

  const openOrderDetails = async (order) => {
    setSelectedOrder(order);
    try {
      const response = await api.get(`/orders/${order.id}`);
      if (response.data.success) {
        setOrderDetails(response.data.order.items);
      }
    } catch (error) {
      toast.error('Failed to load order items');
    }
    setIsModalOpen(true);
  };

  const handleStatusChange = async (id, newStatus) => {
    try {
      await api.put(`/orders/${id}/status`, { order_status: newStatus });
      toast.success('Order status updated');
      fetchOrders();
      if (selectedOrder && selectedOrder.id === id) {
        setSelectedOrder({ ...selectedOrder, order_status: newStatus });
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to update status');
    }
  };

  const handleDeleteOldOrders = async () => {
    if (!window.confirm('Are you sure you want to delete all orders older than 60 days? This action cannot be undone.')) return;
    try {
      const response = await api.delete('/orders/bulk/old');
      toast.success(response.data.message || 'Old orders deleted');
      fetchOrders();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to delete old orders');
    }
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', color: 'var(--text-secondary)', fontWeight: '500' }}>Loading orders...</div>;

  return (
    <div className="admin-page">
      <div className="admin-page-header">
        <h2>Orders Manager</h2>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <select 
            value={statusFilter} 
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '12px' }}
          >
            <option value="all">All Orders</option>
            <option value="pending">Pending (New)</option>
            <option value="contacted">Contacted</option>
            <option value="completed">Completed</option>
            <option value="cancelled">Cancelled</option>
          </select>
          <button className="admin-btn-delete" onClick={handleDeleteOldOrders}>Delete &gt; 60 Days</button>
        </div>
      </div>

      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Order ID</th>
              <th>Date</th>
              <th>Customer</th>
              <th>Phone</th>
              <th>Total</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredOrders.map((order) => (
              <tr key={order.id}>
                <td>#{order.id}</td>
                <td>{new Date(order.created_at).toLocaleDateString()}</td>
                <td>{order.customer_name}</td>
                <td>{order.mobile_number}</td>
                <td>₹{order.grand_total}</td>
                <td>
                  <select 
                    value={order.order_status} 
                    onChange={(e) => handleStatusChange(order.id, e.target.value)}
                    disabled={order.order_status === 'completed' || order.order_status === 'delivered' || order.order_status === 'cancelled'}
                    style={{
                      backgroundColor: (order.order_status === 'completed' || order.order_status === 'delivered' || order.order_status === 'cancelled') ? 'var(--border-color)' : '',
                      color: (order.order_status === 'completed' || order.order_status === 'delivered' || order.order_status === 'cancelled') ? 'var(--text-muted)' : ''
                    }}
                  >
                    <option value="pending">Pending</option>
                    <option value="contacted">Contacted</option>
                    <option value="completed">Completed</option>
                    <option value="cancelled">Cancelled</option>
                  </select>
                </td>
                <td className="action-buttons">
                  <button className="admin-btn-primary" onClick={() => openOrderDetails(order)}>View</button>
                </td>
              </tr>
            ))}
            {filteredOrders.length === 0 && (
              <tr><td colSpan="7" style={{textAlign: 'center', padding: '20px'}}>No orders found for this filter</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title={`Order #${selectedOrder?.id} Details`}>
        {selectedOrder && (
          <div>
            <div style={{ display: 'flex', gap: '20px', marginBottom: '20px', padding: '16px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
              <div style={{ flex: 1 }}>
                <h4 style={{ margin: '0 0 10px 0', color: 'var(--white)' }}>Customer Info</h4>
                <p style={{ margin: '4px 0', fontSize: '13px' }}><strong>Name:</strong> {selectedOrder.customer_name}</p>
                <p style={{ margin: '4px 0', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <strong>Phone:</strong> {selectedOrder.mobile_number}
                  {selectedOrder.mobile_number && (
                    <a href={`https://wa.me/${((selectedOrder.mobile_number || '').replace(/\D/g, '')).length === 10 ? `91${(selectedOrder.mobile_number || '').replace(/\D/g, '')}` : (selectedOrder.mobile_number || '').replace(/\D/g, '')}`} target="_blank" rel="noreferrer" className="admin-btn-whatsapp" style={{ textDecoration: 'none', padding: '3px 8px', fontSize: '10px' }}>WhatsApp</a>
                  )}
                </p>
                <p style={{ margin: '4px 0', fontSize: '13px' }}><strong>Address:</strong> {selectedOrder.address}, {selectedOrder.pin_code}</p>
                {selectedOrder.latitude && (
                  <p style={{ margin: '4px 0', fontSize: '13px' }}><strong>Location:</strong> <a href={`https://maps.google.com/?q=${selectedOrder.latitude},${selectedOrder.longitude}`} target="_blank" rel="noreferrer">View on Map</a></p>
                )}
              </div>
              <div style={{ flex: 1, borderLeft: '1px solid var(--border-color)', paddingLeft: '20px' }}>
                <h4 style={{ margin: '0 0 10px 0', color: 'var(--white)' }}>Items Ordered</h4>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {orderDetails.map(item => (
                    item.primary_image ? (
                      <div key={item.id} style={{ position: 'relative', width: '50px', height: '50px', borderRadius: '6px', overflow: 'hidden', border: '1px solid var(--border-color)' }} title={item.product_name}>
                        <img loading="lazy" 
                          src={`${item.primary_image}`} 
                          alt={item.product_name} 
                          style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                        />
                        <span style={{ position: 'absolute', bottom: 0, right: 0, background: 'rgba(0,0,0,0.7)', color: 'var(--bg-card)', fontSize: '9px', padding: '1px 4px', borderTopLeftRadius: '4px' }}>x{item.quantity}</span>
                      </div>
                    ) : (
                      <div key={item.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '50px', height: '50px', borderRadius: '6px', background: 'var(--border-color)', fontSize: '10px', textAlign: 'center', padding: '2px', color: 'var(--text-muted)' }}>
                        No Img
                      </div>
                    )
                  ))}
                </div>
              </div>
            </div>
            
            <h4>Order Items</h4>
            <table className="admin-table" style={{ marginTop: '10px' }}>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Flavour</th>
                  <th>Qty</th>
                  <th>Price</th>
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>
                {orderDetails.map(item => (
                  <tr key={item.id}>
                    <td>{item.product_name}</td>
                    <td>{item.flavour_name || '-'}</td>
                    <td>{item.quantity}</td>
                    <td>₹{item.unit_price}</td>
                    <td>₹{item.total_price}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Orders;
