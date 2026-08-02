const db = require("../config/db");

// Get All Marquee Products
const getMarqueeProducts = (req, res) => {
  const sql = `
    SELECT m.id as marquee_id, m.display_order, m.status, p.*, p.primary_image as product_image
    FROM marquee_products m
    JOIN products p ON m.product_id = p.id
    ORDER BY m.display_order ASC
  `;
  
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, marquee_products: results });
  });
};

// Add Product to Marquee
const addMarqueeProduct = (req, res) => {
  const { product_id, display_order, status } = req.body;
  
  if (!product_id) return res.status(400).json({ success: false, message: "product_id is required" });

  const sql = "INSERT INTO marquee_products (product_id, display_order, status) VALUES (?, ?, ?)";
  db.query(sql, [product_id, display_order || 0, status !== undefined ? status : 1], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.status(201).json({ success: true, message: "Product added to marquee successfully" });
  });
};

// Update Marquee Product (order/status)
const updateMarqueeProduct = (req, res) => {
  const { id } = req.params;
  const { display_order, status } = req.body;

  const sql = "UPDATE marquee_products SET display_order = ?, status = ? WHERE id = ?";
  db.query(sql, [display_order || 0, status !== undefined ? status : 1, id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Marquee product updated successfully" });
  });
};

// Remove from Marquee
const removeMarqueeProduct = (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM marquee_products WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Product removed from marquee successfully" });
  });
};

module.exports = {
  getMarqueeProducts,
  addMarqueeProduct,
  updateMarqueeProduct,
  removeMarqueeProduct
};
