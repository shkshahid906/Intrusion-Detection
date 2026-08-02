const db = require("../config/db");

// Helper to get generic setting (Reused pattern)
const initTable = () => {
  return new Promise((resolve) => {
    db.query("CREATE TABLE IF NOT EXISTS settings (id INT AUTO_INCREMENT PRIMARY KEY, setting_key VARCHAR(255) UNIQUE NOT NULL, setting_value TEXT)", () => resolve());
  });
};

const getSetting = (key) => {
  return new Promise((resolve, reject) => {
    initTable().then(() => {
      db.query("SELECT setting_value FROM settings WHERE setting_key = ?", [key], (err, results) => {
        if (err) reject(err);
        else resolve(results.length > 0 ? results[0].setting_value : null);
      });
    });
  });
};

const setSetting = (key, value) => {
  return new Promise((resolve, reject) => {
    initTable().then(() => {
      db.query("SELECT * FROM settings WHERE setting_key = ?", [key], (err, results) => {
        if (err) return reject(err);
        if (results.length > 0) {
          db.query("UPDATE settings SET setting_value = ? WHERE setting_key = ?", [value, key], (upErr) => {
             if (upErr) reject(upErr); else resolve();
          });
        } else {
          db.query("INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)", [key, value], (insErr) => {
             if (insErr) reject(insErr); else resolve();
          });
        }
      });
    });
  });
};

// --- SEO SETTINGS CRUD ---
const getSeoSettings = async (req, res) => {
  try {
    const data = await getSetting("global_seo_settings");
    res.json({ success: true, seo: data ? JSON.parse(data) : {} });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const updateSeoSettings = async (req, res) => {
  try {
    // Expecting metaTitle, metaDesc, analytics, pixel etc in body
    await setSetting("global_seo_settings", JSON.stringify(req.body));
    res.json({ success: true, message: "Global SEO settings updated successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

// --- SITEMAP.XML GENERATOR ---
const generateSitemap = (req, res) => {
  // Assuming frontend runs on the same domain or we have a base URL in env
  const baseUrl = process.env.FRONTEND_URL || "http://localhost:3000";
  
  // Fetch dynamic routes
  db.query("SELECT slug, updated_at FROM products WHERE status = 1", (pErr, products) => {
    if (pErr) return res.status(500).send("Database error");

    db.query("SELECT slug FROM categories WHERE status = 1", (cErr, categories) => {
      if (cErr) return res.status(500).send("Database error");

      let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
      xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n`;

      // Static routes
      const staticRoutes = ["/", "/products", "/about", "/contact"];
      staticRoutes.forEach(route => {
        xml += `  <url>\n    <loc>${baseUrl}${route}</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.8</priority>\n  </url>\n`;
      });

      // Categories
      categories.forEach(cat => {
        xml += `  <url>\n    <loc>${baseUrl}/category/${cat.slug}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
      });

      // Products
      products.forEach(prod => {
        xml += `  <url>\n    <loc>${baseUrl}/product/${prod.slug}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.9</priority>\n  </url>\n`;
      });

      xml += `</urlset>`;

      res.header("Content-Type", "application/xml");
      res.send(xml);
    });
  });
};

// --- ROBOTS.TXT GENERATOR ---
const generateRobots = (req, res) => {
  const baseUrl = process.env.FRONTEND_URL || "http://localhost:3000";
  const txt = `User-agent: *\nDisallow: /admin/\nDisallow: /api/\n\nSitemap: ${baseUrl}/sitemap.xml`;
  
  res.header("Content-Type", "text/plain");
  res.send(txt);
};

module.exports = {
  getSeoSettings,
  updateSeoSettings,
  generateSitemap,
  generateRobots
};
