const express = require("express");
const router = express.Router();

const verifyToken = require("../middleware/authMiddleware");

const {
  createFlavour,
  getFlavours,
  getFlavourById,
  updateFlavour,
  deleteFlavour,
} = require("../controllers/flavourController");

router.post("/", verifyToken, createFlavour);

router.get("/", getFlavours);

router.get("/:id", getFlavourById);

router.put("/:id", verifyToken, updateFlavour);

router.delete("/:id", verifyToken, deleteFlavour);

module.exports = router;
