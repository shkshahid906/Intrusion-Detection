const db = require("../config/db");

const getDashboardStats = async (req, res) => {
  const query = (sql, args = []) => new Promise((resolve, reject) => {
    db.query(sql, args, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });

  try {
    const productsCount = await query('SELECT COUNT(*) as count FROM products');
    const categoriesCount = await query('SELECT COUNT(*) as count FROM categories');
    
    // Some versions use flavours, some use product_flavours. Try flavours first, fallback if error.
    let flavoursCount = [{ count: 0 }];
    try { flavoursCount = await query('SELECT COUNT(*) as count FROM flavours'); } catch(e) {}
    
    const ordersCount = await query('SELECT COUNT(*) as count FROM orders');
    const enquiriesCount = await query('SELECT COUNT(*) as count FROM enquiries');

    const stats = {
      products: productsCount[0].count,
      categories: categoriesCount[0].count,
      flavours: flavoursCount[0].count,
      orders: ordersCount[0].count,
      enquiries: enquiriesCount[0].count
    };

    const recentOrders = await query('SELECT id, customer_name, grand_total, order_status, created_at FROM orders ORDER BY created_at DESC LIMIT 5');
    
    const lowStockProducts = await query("SELECT id, product_name, stock as current_stock, 'Product' as type FROM products WHERE stock < 10 AND status='active'");
    let lowStockFlavours = [];
    try {
      lowStockFlavours = await query("SELECT pf.id, p.product_name, pf.flavour_name, pf.stock as current_stock, 'Flavour' as type FROM product_flavours pf JOIN products p ON pf.product_id = p.id WHERE pf.stock < 10 AND p.status='active'");
    } catch(e) {}

    const lowStockItems = [...lowStockProducts, ...lowStockFlavours].sort((a, b) => a.current_stock - b.current_stock).slice(0, 15); // limit to 15 items to not overwhelm UI

    res.json({ success: true, stats, recentOrders, lowStockItems });

  } catch (error) {
    console.error("Dashboard Stats Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = {
  getDashboardStats
};
