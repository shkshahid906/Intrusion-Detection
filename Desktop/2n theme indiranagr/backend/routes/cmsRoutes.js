const express = require("express");
const router = express.Router();
const verifyToken = require("../middleware/authMiddleware");
const createUpload = require("../middleware/uploadFactory");
const uploadCms = createUpload("cms");

const {
  getAboutUs, updateAboutUs,
  getContactInfo, updateContactInfo,
  getFooterInfo, updateFooterInfo,
  getWhyChooseUs, addWhyChooseUs, updateWhyChooseUs, deleteWhyChooseUs,
  getWhatsappSettings, updateWhatsappSettings,
  getDeliveryAreas, addDeliveryArea, updateDeliveryArea, deleteDeliveryArea
} = require("../controllers/cmsController");


// Public routes
router.get("/about", getAboutUs);
router.get("/contact-info", getContactInfo);
router.get("/footer", getFooterInfo);
router.get("/why-choose-us", getWhyChooseUs);
router.get("/whatsapp", getWhatsappSettings);

// Protected routes (Admin)
router.put("/about", verifyToken, uploadCms.array("images", 10), updateAboutUs);
router.put("/contact-info", verifyToken, uploadCms.single("logo_image"), updateContactInfo);
router.put("/footer", verifyToken, updateFooterInfo);
router.put("/whatsapp", verifyToken, updateWhatsappSettings);

router.post("/why-choose-us", verifyToken, addWhyChooseUs);
router.put("/why-choose-us/:id", verifyToken, updateWhyChooseUs);
router.delete("/why-choose-us/:id", verifyToken, deleteWhyChooseUs);

router.get("/delivery-areas", getDeliveryAreas);
router.post("/delivery-areas", verifyToken, addDeliveryArea);
router.put("/delivery-areas/:id", verifyToken, updateDeliveryArea);
router.delete("/delivery-areas/:id", verifyToken, deleteDeliveryArea);

module.exports = router;
