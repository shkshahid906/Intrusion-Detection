const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");

const {
  getMarqueeProducts,
  addMarqueeProduct,
  updateMarqueeProduct,
  removeMarqueeProduct
} = require("../controllers/marqueeController");

// Public route
router.get("/", getMarqueeProducts);

// Protected routes (Admin)
router.post("/", verifyToken, addMarqueeProduct);
router.put("/:id", verifyToken, updateMarqueeProduct);
router.delete("/:id", verifyToken, removeMarqueeProduct);

module.exports = router;
