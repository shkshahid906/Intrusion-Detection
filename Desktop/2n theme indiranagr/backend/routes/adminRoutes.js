const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");
const { getDashboardStats } = require("../controllers/adminController");

router.get("/profile", verifyToken, (req, res) => {
  res.json({
    success: true,
    admin: req.admin,
  });
});

router.get("/stats", verifyToken, getDashboardStats);

module.exports = router;