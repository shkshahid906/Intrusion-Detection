const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");

const {
  getSeoSettings,
  updateSeoSettings,
  generateSitemap,
  generateRobots
} = require("../controllers/seoController");

// Public Dynamic Files (Often mounted at root, but we provide them via API for flexibility)
router.get("/sitemap.xml", generateSitemap);
router.get("/robots.txt", generateRobots);

// Public Settings fetch (for React helmet)
router.get("/settings", getSeoSettings);

// Protected Admin updates
router.put("/settings", verifyToken, updateSeoSettings);

module.exports = router;
