const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");
const createUpload = require("../middleware/uploadFactory");
const uploadBanner = createUpload("banners");

const {
  createBanner,
  getBanners,
  updateBanner,
  deleteBanner
} = require("../controllers/bannerController");

// Public routes
router.get("/", getBanners);

// Protected routes (Admin)
router.post("/", verifyToken, uploadBanner.single("image"), createBanner);
router.put("/:id", verifyToken, uploadBanner.single("image"), updateBanner);
router.delete("/:id", verifyToken, deleteBanner);

module.exports = router;
