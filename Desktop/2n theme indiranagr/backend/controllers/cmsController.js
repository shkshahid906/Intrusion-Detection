const db = require("../config/db");

// --- ABOUT US ---
const getAboutUs = (req, res) => {
  db.query("SELECT * FROM about_us LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    let about = results[0] || {};
    if (about.images) {
      try { about.images = JSON.parse(about.images); } catch(e) { about.images = []; }
    } else {
      about.images = [];
      // Backward compatibility
      if (about.image_path) about.images.push(about.image_path);
    }
    res.json({ success: true, about: about });
  });
};

const updateAboutUs = (req, res) => {
  const { title, description } = req.body;
  let existingImages = req.body.existingImages || [];
  if (typeof existingImages === 'string') {
    try { existingImages = JSON.parse(existingImages); } catch(e) { existingImages = []; }
  }
  
  db.query("SELECT id, image_path, images FROM about_us LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    
    let newImages = [...existingImages];
    
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        newImages.push(`/uploads/cms/${file.filename}`);
      });
    }

    if (results.length > 0) {
      db.query("UPDATE about_us SET title=?, description=?, images=? WHERE id=?", [title, description, JSON.stringify(newImages), results[0].id], (upErr) => {
        if (upErr) return res.status(500).json({ success: false, error: upErr.message });
        res.json({ success: true, message: "About Us updated" });
      });
    } else {
      db.query("INSERT INTO about_us (title, description, images) VALUES (?, ?, ?)", [title, description, JSON.stringify(newImages)], (inErr) => {
        if (inErr) return res.status(500).json({ success: false, error: inErr.message });
        res.json({ success: true, message: "About Us created" });
      });
    }
  });
};

// --- CONTACT INFO ---
const getContactInfo = (req, res) => {
  db.query("SELECT * FROM contact_information LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, contactInfo: results[0] || {} });
  });
};

const updateContactInfo = (req, res) => {
  const { company_name, phone, email, address, google_map_link, facebook, instagram, twitter, youtube } = req.body;
  const sharedPhone = (phone || "").replace(/\D/g, "");
  const uploadedLogo = req.file ? `/uploads/cms/${req.file.filename}` : null;
  
  db.query("SELECT id, company_name, logo_image FROM contact_information LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    const logoImage = uploadedLogo || req.body.logo_image || results[0]?.logo_image || "";
    const companyName = company_name !== undefined ? company_name : (results[0]?.company_name || "");
    
    if (results.length > 0) {
      const sql = `UPDATE contact_information SET company_name=?, phone=?, whatsapp=?, email=?, address=?, google_map_link=?, facebook=?, instagram=?, twitter=?, youtube=?, logo_image=? WHERE id=?`;
      db.query(sql, [companyName, sharedPhone, sharedPhone, email, address, google_map_link, facebook, instagram, twitter, youtube, logoImage, results[0].id], (upErr) => {
        if (upErr) return res.status(500).json({ success: false, error: upErr.message });
        res.json({ success: true, message: "Contact info updated" });
      });
    } else {
      const sql = `INSERT INTO contact_information (company_name, phone, whatsapp, email, address, google_map_link, facebook, instagram, twitter, youtube, logo_image) VALUES (?,?,?,?,?,?,?,?,?,?,?)`;
      db.query(sql, [companyName, sharedPhone, sharedPhone, email, address, google_map_link, facebook, instagram, twitter, youtube, logoImage], (inErr) => {
        if (inErr) return res.status(500).json({ success: false, error: inErr.message });
        res.json({ success: true, message: "Contact info created" });
      });
    }
  });
};

// --- FOOTER CMS ---
const getFooterInfo = (req, res) => {
  db.query("SELECT * FROM footer_settings LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, footer: results[0] || {} });
  });
};

const updateFooterInfo = (req, res) => {
  const { footer_text, copyright_text, footer_logo_text } = req.body;
  db.query("SELECT id FROM footer_settings LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    
    if (results.length > 0) {
      db.query("UPDATE footer_settings SET footer_text=?, copyright_text=?, footer_logo_text=? WHERE id=?", [footer_text, copyright_text, footer_logo_text, results[0].id], (upErr) => {
        if (upErr) return res.status(500).json({ success: false, error: upErr.message });
        res.json({ success: true, message: "Footer updated" });
      });
    } else {
      db.query("INSERT INTO footer_settings (footer_text, copyright_text, footer_logo_text) VALUES (?, ?, ?)", [footer_text, copyright_text, footer_logo_text], (inErr) => {
        if (inErr) return res.status(500).json({ success: false, error: inErr.message });
        res.json({ success: true, message: "Footer created" });
      });
    }
  });
};

// --- WHY CHOOSE US ---
const getWhyChooseUs = (req, res) => {
  db.query("SELECT * FROM why_choose_us ORDER BY display_order ASC", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, items: results });
  });
};

const addWhyChooseUs = (req, res) => {
  const { title, description, icon, display_order, status } = req.body;
  db.query("INSERT INTO why_choose_us (title, description, icon, display_order, status) VALUES (?, ?, ?, ?, ?)", 
    [title, description, icon, display_order || 0, status || 'active'], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.status(201).json({ success: true, message: "Feature added" });
  });
};

const updateWhyChooseUs = (req, res) => {
  const { id } = req.params;
  const { title, description, icon, display_order, status } = req.body;
  db.query("UPDATE why_choose_us SET title=?, description=?, icon=?, display_order=?, status=? WHERE id=?", 
    [title, description, icon, display_order, status, id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Feature updated" });
  });
};

const deleteWhyChooseUs = (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM why_choose_us WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Feature deleted" });
  });
};

// --- WHATSAPP SETTINGS ---
const formatWaMeNumber = (number) => {
  const digits = (number || "").replace(/\D/g, "");
  return digits.length === 10 ? `91${digits}` : digits;
};

const getWhatsappSettings = (req, res) => {
  db.query("SELECT * FROM whatsapp_settings LIMIT 1", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    const whatsapp = results[0] || {};

    db.query("SELECT phone FROM contact_information LIMIT 1", (contactErr, contactResults) => {
      if (contactErr) return res.status(500).json({ success: false, error: contactErr.message });
      const savedPhone = contactResults[0]?.phone || "";

      const defaultMsg = whatsapp.default_message || "Hello! I would like to know more about your vapes and flavours available.";
      const defaultTemplate = whatsapp.custom_template || `━━━━━━━━━━━━━━━━━━━━
🛍️ *VAPES INDIRANAGAR | ORDER CONFIRMATION*
━━━━━━━━━━━━━━━━━━━━

*Order ID:* #[ORDER_ID]
*Status:* New Order Received

*CUSTOMER DETAILS*
👤 *Name:* [CUSTOMER_NAME]

*ORDER SUMMARY*
──────────────
[ITEMS]
──────────────

*TOTAL DUE:* ₹[TOTAL]
━━━━━━━━━━━━━━━━━━━━`;

      res.json({
        success: true,
        whatsapp: {
          ...whatsapp,
          default_message: defaultMsg,
          custom_template: defaultTemplate,
          business_number: formatWaMeNumber(savedPhone),
          display_number: savedPhone
        }
      });
    });
  });
};

const updateWhatsappSettings = (req, res) => {
  const { default_message, custom_template } = req.body;

  db.query("SELECT phone FROM contact_information LIMIT 1", (contactErr, contactResults) => {
    if (contactErr) return res.status(500).json({ success: false, error: contactErr.message });
    const savedPhone = contactResults[0]?.phone || "";

    db.query("SELECT id FROM whatsapp_settings LIMIT 1", (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      
      if (results.length > 0) {
        db.query("UPDATE whatsapp_settings SET business_number=?, default_message=?, custom_template=? WHERE id=?", 
          [savedPhone, default_message, custom_template, results[0].id], (upErr) => {
          if (upErr) return res.status(500).json({ success: false, error: upErr.message });
          res.json({ success: true, message: "WhatsApp settings updated" });
        });
      } else {
        db.query("INSERT INTO whatsapp_settings (business_number, default_message, custom_template) VALUES (?, ?, ?)", 
          [savedPhone, default_message, custom_template], (inErr) => {
          if (inErr) return res.status(500).json({ success: false, error: inErr.message });
          res.json({ success: true, message: "WhatsApp settings created" });
        });
      }
    });
  });
};

// --- DELIVERY AREAS ---
const getDeliveryAreas = (req, res) => {
  db.query("SELECT * FROM delivery_areas ORDER BY display_order ASC", (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, areas: results });
  });
};

const addDeliveryArea = (req, res) => {
  const { main_area, sub_areas, link_text, link_url, display_order, status } = req.body;
  db.query("INSERT INTO delivery_areas (main_area, sub_areas, link_text, link_url, display_order, status) VALUES (?, ?, ?, ?, ?, ?)", 
    [main_area, sub_areas, link_text || 'Vape delivery here →', link_url || '/#products', display_order || 0, status || 'active'], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.status(201).json({ success: true, message: "Delivery Area added" });
  });
};

const updateDeliveryArea = (req, res) => {
  const { id } = req.params;
  const { main_area, sub_areas, link_text, link_url, display_order, status } = req.body;
  db.query("UPDATE delivery_areas SET main_area=?, sub_areas=?, link_text=?, link_url=?, display_order=?, status=? WHERE id=?", 
    [main_area, sub_areas, link_text, link_url, display_order, status, id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Delivery Area updated" });
  });
};

const deleteDeliveryArea = (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM delivery_areas WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Delivery Area deleted" });
  });
};

module.exports = {
  getAboutUs, updateAboutUs,
  getContactInfo, updateContactInfo,
  getFooterInfo, updateFooterInfo,
  getWhyChooseUs, addWhyChooseUs, updateWhyChooseUs, deleteWhyChooseUs,
  getWhatsappSettings, updateWhatsappSettings,
  getDeliveryAreas, addDeliveryArea, updateDeliveryArea, deleteDeliveryArea
};
