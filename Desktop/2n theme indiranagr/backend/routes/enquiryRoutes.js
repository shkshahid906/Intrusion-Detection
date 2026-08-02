const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");

const {
  createEnquiry,
  getEnquiries,
  deleteEnquiry,
  deleteOldEnquiries,
  deleteAllEnquiries
} = require("../controllers/enquiryController");

// Public routes
router.post("/", createEnquiry);

// Protected routes (Admin)
router.delete("/bulk/old", verifyToken, deleteOldEnquiries);
router.delete("/bulk/all", verifyToken, deleteAllEnquiries);

router.get("/", verifyToken, getEnquiries);
router.delete("/:id", verifyToken, deleteEnquiry);

module.exports = router;
