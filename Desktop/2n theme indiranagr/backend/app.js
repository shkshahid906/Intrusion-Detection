const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const categoryRoutes = require("./routes/categoryRoutes");
const flavourRoutes = require("./routes/flavourRoutes");
const productRoutes = require("./routes/productRoutes");
const bannerRoutes = require("./routes/bannerRoutes");
const marqueeRoutes = require("./routes/marqueeRoutes");
const cmsRoutes = require("./routes/cmsRoutes");
const orderRoutes = require("./routes/orderRoutes");
const enquiryRoutes = require("./routes/enquiryRoutes");
const seoRoutes = require("./routes/seoRoutes");
const path = require("path");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(compression());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/flavours", flavourRoutes);
app.use("/api/products", productRoutes);
app.use("/api/banners", bannerRoutes);
app.use("/api/marquee", marqueeRoutes);
app.use("/api/cms", cmsRoutes);
app.use("/api/orders", orderRoutes);
app.use("/api/enquiries", enquiryRoutes);
app.use("/api/seo", seoRoutes);

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Vapes Indiranagar API Working",
  });
});

module.exports = app;