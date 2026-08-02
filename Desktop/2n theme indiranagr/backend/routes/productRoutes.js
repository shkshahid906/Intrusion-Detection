const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");
const upload = require("../middleware/uploadMiddleware");

const {
  createProduct,
  getProducts,
  getProductById,
  updateProduct,
  deleteProduct,
  deleteProductImage,
  getProductImages,
  getProductFlavours,
  updateProductFlavours,
  removeProductFlavour
} = require("../controllers/productController");

// Public routes
router.get("/", getProducts);
router.get("/:id", getProductById);
router.get("/:id/images", getProductImages);
router.get("/:id/flavours", getProductFlavours);

// Protected routes (Admin)
// 'images' and 'primary_image' field names match the FormData keys we will use in frontend
router.post("/", verifyToken, upload.fields([{ name: "primary_image", maxCount: 1 }, { name: "images", maxCount: 10 }]), createProduct);
router.put("/:id", verifyToken, upload.fields([{ name: "primary_image", maxCount: 1 }, { name: "images", maxCount: 10 }]), updateProduct);
router.delete("/:id", verifyToken, deleteProduct);

// Image specific deletion route
router.delete("/image/:imageId", verifyToken, deleteProductImage);

// Flavour specific routes
router.put("/:id/flavours", verifyToken, updateProductFlavours); // bulk assign/update
router.delete("/:id/flavours/:flavourId", verifyToken, removeProductFlavour); // remove single

module.exports = router;
