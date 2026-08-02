"use client";

import React, { useState, useEffect } from 'react';
import api from '../../../services/api';
import { toast } from 'react-toastify';
import { FiShoppingBag, FiBox, FiGrid, FiDroplet, FiMessageSquare } from 'react-icons/fi';
import { useRouter } from 'next/navigation';
import './Dashboard.css';

const Dashboard = () => {
  const router = useRouter();
  const [stats, setStats] = useState({
    products: 0,
    categories: 0,
    flavours: 0,
    orders: 0,
    enquiries: 0
  });
  const [recentOrders, setRecentOrders] = useState([]);
  const [lowStockItems, setLowStockItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await api.get('/admin/stats');
        if (response.data.success) {
          setStats(response.data.stats);
          setRecentOrders(response.data.recentOrders || []);
          setLowStockItems(response.data.lowStockItems || []);
        }
      } catch (error) {
        toast.error('Failed to load dashboard statistics');
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading) return (
    <div className="dashboard-loading">
      <div className="spinner"></div>
      <p>Loading statistics...</p>
    </div>
  );

  const statCards = [
    { label: 'Total Orders', value: stats.orders, icon: <FiShoppingBag /> },
    { label: 'Total Products', value: stats.products, icon: <FiBox /> },
    { label: 'Categories', value: stats.categories, icon: <FiGrid /> },
    { label: 'Flavours', value: stats.flavours, icon: <FiDroplet /> },
    { label: 'Enquiries', value: stats.enquiries, icon: <FiMessageSquare /> }
  ];

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h2>Dashboard Overview</h2>
        <p>Welcome back! Here's what's happening with your store today.</p>
      </div>
      
      <div className="stat-cards-grid">
        {statCards.map((stat, idx) => (
          <div key={idx} className="stat-card">
            <div className="stat-card-icon">
              {stat.icon}
            </div>
            <div className="stat-card-content">
              <h4>{stat.label}</h4>
              <h2>{stat.value}</h2>
            </div>
            <div className="stat-card-bg-icon">
              {stat.icon}
            </div>
          </div>
        ))}
      </div>

      <div className="dashboard-widgets-grid">
        
        {/* Recent Orders Widget */}
        <div className="dashboard-widget">
          <div className="widget-header">
            <h3>Recent Orders</h3>
          </div>
          <div className="widget-content">
            {recentOrders.length === 0 ? (
              <p className="no-data">No recent orders found.</p>
            ) : (
              <div className="table-responsive">
                <table className="widget-table">
                  <thead>
                    <tr>
                      <th>Order ID</th>
                      <th>Customer</th>
                      <th>Total</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentOrders.map(order => (
                      <tr key={order.id} onClick={() => router.push('/admin/orders')} style={{ cursor: 'pointer' }}>
                        <td>#{order.id}</td>
                        <td>{order.customer_name}</td>
                        <td>₹{order.grand_total}</td>
                        <td>
                          <span className={`status-badge status-${order.order_status?.toLowerCase()}`}>
                            {order.order_status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Low Stock Widget */}
        <div className="dashboard-widget">
          <div className="widget-header">
            <h3>Low Stock Alerts</h3>
          </div>
          <div className="widget-content">
            {lowStockItems.length === 0 ? (
              <p className="no-data">All products are sufficiently stocked.</p>
            ) : (
              <div className="table-responsive">
                <table className="widget-table">
                  <thead>
                    <tr>
                      <th>Item</th>
                      <th>Type</th>
                      <th>Stock</th>
                    </tr>
                  </thead>
                  <tbody>
                    {lowStockItems.map((item, idx) => (
                      <tr key={`${item.id}-${item.type}-${idx}`} onClick={() => router.push('/admin/products')} style={{ cursor: 'pointer' }}>
                        <td>
                          {item.product_name} 
                          {item.flavour_name ? ` (${item.flavour_name})` : ''}
                        </td>
                        <td><span className="type-badge">{item.type}</span></td>
                        <td>
                          <span className="stock-alert">{item.current_stock}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;
