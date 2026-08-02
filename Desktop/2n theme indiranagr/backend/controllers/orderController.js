const db = require("../config/db");

// Create Order (Checkout API)
const createOrder = (req, res) => {
  const { name, phone, address, pin, lat, lng, cartItems, totalAmount } = req.body;

  if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
    return res.status(400).json({ success: false, message: "Cart items are required" });
  }

  const sql = `
    INSERT INTO orders (customer_name, mobile_number, address, pin_code, latitude, longitude, grand_total, total_items, order_status) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `;

  const totalItems = cartItems.reduce((acc, item) => acc + item.quantity, 0);

  db.query(sql, [name, phone, address, pin, lat, lng, totalAmount || 0, totalItems], (err, result) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    
    const orderId = result.insertId;

    // Prepare order items
    const itemValues = cartItems.map(item => [
      orderId,
      item.product_id,
      item.flavour || "",
      item.quantity,
      item.price || 0,
      (item.price || 0) * (item.quantity || 1)
    ]);

    db.query(
      "INSERT INTO order_items (order_id, product_id, flavour_name, quantity, unit_price, total_price) VALUES ?",
      [itemValues],
      (itemErr) => {
        if (itemErr) {
          // If items fail, we should ideally rollback, but for now we log it.
          console.error("Failed to insert order items:", itemErr);
          return res.status(500).json({ success: false, error: "Order created but failed to save items" });
        }

        res.status(201).json({ 
          success: true, 
          message: "Order placed successfully",
          orderId 
        });
      }
    );
  });
};

// Get All Orders (Admin)
const getOrders = (req, res) => {
  db.query("SELECT * FROM orders ORDER BY created_at DESC", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, orders: results });
  });
};

// Get Single Order Details (Admin)
const getOrderDetails = (req, res) => {
  const { id } = req.params;

  db.query("SELECT * FROM orders WHERE id = ?", [id], (err, orderResults) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    if (orderResults.length === 0) return res.status(404).json({ success: false, message: "Order not found" });

    const order = orderResults[0];

    const sqlItems = `
      SELECT oi.*, 
             IFNULL(p.product_name, 'Deleted Product') as product_name, 
             p.primary_image as primary_image 
      FROM order_items oi
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = ?
    `;

    db.query(sqlItems, [id], (itemErr, itemResults) => {
      if (itemErr) {
        console.error("Order items fetch error:", itemErr);
        return res.status(500).json({ success: false, error: itemErr.message });
      }
      
      order.items = itemResults;
      res.json({ success: true, order });
    });
  });
};

// Helper function to reduce stock and increment sales when an order is completed
const reduceStockForOrder = (orderId) => {
  db.query("SELECT * FROM order_items WHERE order_id = ?", [orderId], (err, items) => {
    if (err || !items) {
      console.error("Failed to fetch order items for stock reduction:", err);
      return;
    }

    items.forEach(item => {
      const qty = parseInt(item.quantity) || 1;
      
      // 1. If it has a specific flavour, reduce stock from product_flavours
      if (item.flavour_name && item.flavour_name.trim() !== "") {
        db.query(
          "UPDATE product_flavours SET stock = CASE WHEN stock >= ? THEN stock - ? ELSE 0 END WHERE product_id = ? AND flavour_name = ?", 
          [qty, qty, item.product_id, item.flavour_name],
          (err) => { if (err) console.error("Flavour stock update error:", err.message); }
        );
      } else {
        // 2. Otherwise, reduce stock from the main products table
        db.query(
          "UPDATE products SET stock = CASE WHEN stock >= ? THEN stock - ? ELSE 0 END WHERE id = ?", 
          [qty, qty, item.product_id],
          (err) => { if (err) console.error("Product stock update error:", err.message); }
        );
      }
      
      // 3. Increment the sales_count for the product (for best sellers analytics)
      db.query(
        "UPDATE products SET sales_count = IFNULL(sales_count, 0) + ? WHERE id = ?", 
        [qty, item.product_id],
        (err) => { if (err) console.error("Sales count update error:", err.message); }
      );
    });
  });
};

// Update Order Status (Admin)
const updateOrderStatus = (req, res) => {
  const { id } = req.params;
  const status = req.body.order_status || req.body.status;

  // First, check what the current status of the order is
  db.query("SELECT order_status FROM orders WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    if (results.length === 0) return res.status(404).json({ success: false, message: "Order not found" });

    const currentStatus = results[0].order_status.toLowerCase();
    const newStatus = status.toLowerCase();

    if (currentStatus === 'completed' || currentStatus === 'delivered' || currentStatus === 'cancelled') {
      return res.status(400).json({ success: false, message: "Order is already completed or cancelled and cannot be modified." });
    }

    // Update the status in the database
    db.query("UPDATE orders SET order_status = ? WHERE id = ?", [status, id], (updateErr) => {
      if (updateErr) return res.status(500).json({ success: false, error: updateErr.message });
      
      // If the order is newly being marked as 'delivered' or 'completed', trigger the stock reduction
      const isNowCompleted = (newStatus === 'delivered' || newStatus === 'completed');
      const wasAlreadyCompleted = (currentStatus === 'delivered' || currentStatus === 'completed');

      if (isNowCompleted && !wasAlreadyCompleted) {
        reduceStockForOrder(id);
      }

      res.json({ success: true, message: "Order status updated successfully" });
    });
  });
};

// Delete Order (Admin)
const deleteOrder = (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM order_items WHERE order_id = ?", [id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    
    db.query("DELETE FROM orders WHERE id = ?", [id], (delErr) => {
      if (delErr) return res.status(500).json({ success: false, error: delErr.message });
      res.json({ success: true, message: "Order deleted successfully" });
    });
  });
};

// Delete Orders Older Than 60 Days (Admin Bulk)
const deleteOldOrders = (req, res) => {
  const sixtyDaysAgo = new Date();
  sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);
  
  // We need to delete from order_items first, then orders.
  // Using a subquery or joining isn't always safe with DELETE in MySQL unless done carefully,
  // but we can do a multi-table delete or delete items matching the orders.
  
  const sqlDeleteItems = `
    DELETE oi FROM order_items oi
    JOIN orders o ON oi.order_id = o.id
    WHERE o.created_at < ?
  `;

  db.query(sqlDeleteItems, [sixtyDaysAgo], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    
    const sqlDeleteOrders = "DELETE FROM orders WHERE created_at < ?";
    db.query(sqlDeleteOrders, [sixtyDaysAgo], (delErr, result) => {
      if (delErr) return res.status(500).json({ success: false, error: delErr.message });
      res.json({ success: true, message: `Deleted ${result.affectedRows} old orders successfully` });
    });
  });
};

// Delete All Orders (Admin Bulk) removed to protect transactions

module.exports = {
  createOrder,
  getOrders,
  getOrderDetails,
  updateOrderStatus,
  deleteOrder,
  deleteOldOrders
};
