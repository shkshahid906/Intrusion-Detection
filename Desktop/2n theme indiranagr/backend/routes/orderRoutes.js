const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");

const {
  createOrder,
  getOrders,
  getOrderDetails,
  updateOrderStatus,
  deleteOrder,
  deleteOldOrders
} = require("../controllers/orderController");

// Public routes
router.post("/", createOrder); // Checkout API

// Protected routes (Admin)
// NOTE: Bulk deletes must come before /:id so 'bulk' isn't treated as an ID
router.delete("/bulk/old", verifyToken, deleteOldOrders);

router.get("/", verifyToken, getOrders);
router.get("/:id", verifyToken, getOrderDetails);
router.put("/:id/status", verifyToken, updateOrderStatus);
router.delete("/:id", verifyToken, deleteOrder);

module.exports = router;
