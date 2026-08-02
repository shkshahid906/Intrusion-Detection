const db = require("../config/db");

// Create Enquiry (Public)
const createEnquiry = (req, res) => {
  const { name, phone, email, message, type } = req.body;

  // type could be 'ContactForm' or 'WhatsApp'
  const sql = "INSERT INTO enquiries (name, phone, email, message, enquiry_type) VALUES (?, ?, ?, ?, ?)";
  
  db.query(sql, [name, phone, email, message, type || 'ContactForm'], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.status(201).json({ success: true, message: "Enquiry submitted successfully" });
  });
};

// Get All Enquiries (Admin)
const getEnquiries = (req, res) => {
  db.query("SELECT * FROM enquiries ORDER BY created_at DESC", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, enquiries: results });
  });
};

// Delete Enquiry (Admin)
const deleteEnquiry = (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM enquiries WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Enquiry deleted successfully" });
  });
};

// Delete Enquiries Older Than 30 Days (Admin)
const deleteOldEnquiries = (req, res) => {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  
  db.query("DELETE FROM enquiries WHERE created_at < ?", [thirtyDaysAgo], (err, result) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: `Deleted ${result.affectedRows} old enquiries successfully` });
  });
};

// Delete All Enquiries (Admin)
const deleteAllEnquiries = (req, res) => {
  db.query("DELETE FROM enquiries", (err, result) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: `Deleted all ${result.affectedRows} enquiries successfully` });
  });
};

module.exports = {
  createEnquiry,
  getEnquiries,
  deleteEnquiry,
  deleteOldEnquiries,
  deleteAllEnquiries
};
