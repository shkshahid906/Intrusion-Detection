const db = require("../config/db");
const fs = require("fs");
const path = require("path");

// Create Banner
const createBanner = (req, res) => {
  const { title, subtitle, button_text, button_link, display_order, status } = req.body;
  const image_path = req.file ? `/uploads/banners/${req.file.filename}` : null;

  if (!image_path) {
    return res.status(400).json({ success: false, message: "Banner image is required" });
  }

  const sql = "INSERT INTO banners (title, subtitle, image_path, button_text, button_link, display_order, status) VALUES (?, ?, ?, ?, ?, ?, ?)";
  db.query(sql, [title || "", subtitle || "", image_path, button_text || "", button_link || "", display_order || 0, status || 'active'], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.status(201).json({ success: true, message: "Banner created successfully" });
  });
};

// Get All Banners
const getBanners = (req, res) => {
  db.query("SELECT * FROM banners ORDER BY display_order ASC", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, banners: results });
  });
};

// Update Banner
const updateBanner = (req, res) => {
  const { id } = req.params;
  const { title, subtitle, button_text, button_link, display_order, status } = req.body;
  
  if (req.file) {
    // Has new image, delete old one first
    db.query("SELECT image_path FROM banners WHERE id = ?", [id], (err, results) => {
      if (!err && results.length > 0 && results[0].image_path) {
        const filePath = path.join(__dirname, "..", results[0].image_path);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
      
      const newImagePath = `/uploads/banners/${req.file.filename}`;
      const sql = "UPDATE banners SET title=?, subtitle=?, image_path=?, button_text=?, button_link=?, display_order=?, status=? WHERE id=?";
      db.query(sql, [title, subtitle, newImagePath, button_text, button_link, display_order, status, id], (upErr) => {
        if (upErr) return res.status(500).json({ success: false, error: upErr.message });
        res.json({ success: true, message: "Banner updated successfully" });
      });
    });
  } else {
    // No new image
    const sql = "UPDATE banners SET title=?, subtitle=?, button_text=?, button_link=?, display_order=?, status=? WHERE id=?";
    db.query(sql, [title, subtitle, button_text, button_link, display_order, status, id], (err) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, message: "Banner updated successfully" });
    });
  }
};

// Delete Banner
const deleteBanner = (req, res) => {
  const { id } = req.params;
  
  db.query("SELECT image_path FROM banners WHERE id = ?", [id], (err, results) => {
    if (!err && results.length > 0 && results[0].image_path) {
      const filePath = path.join(__dirname, "..", results[0].image_path);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    
    db.query("DELETE FROM banners WHERE id = ?", [id], (delErr) => {
      if (delErr) return res.status(500).json({ success: false, error: delErr.message });
      res.json({ success: true, message: "Banner deleted successfully" });
    });
  });
};

module.exports = {
  createBanner,
  getBanners,
  updateBanner,
  deleteBanner
};
