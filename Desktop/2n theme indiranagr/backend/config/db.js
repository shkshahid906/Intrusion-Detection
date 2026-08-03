const mysql = require("mysql2");

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  charset: 'utf8mb4'
});

connection.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    return;
  }

  console.log("MySQL Connected Successfully");

  // Ensure nicotine_strength column exists in products table
  connection.query("SHOW COLUMNS FROM products LIKE 'nicotine_strength'", (cErr, cResult) => {
    if (!cErr && cResult.length === 0) {
      connection.query("ALTER TABLE products ADD COLUMN nicotine_strength VARCHAR(50) DEFAULT ''", (aErr) => {
        if (aErr) console.error("Error adding nicotine_strength column:", aErr);
        else console.log("Added nicotine_strength column to products table.");
      });
    }
  });

  connection.query("SHOW COLUMNS FROM contact_information LIKE 'logo_image'", (cErr, cResult) => {
    if (!cErr && cResult.length === 0) {
      connection.query("ALTER TABLE contact_information ADD COLUMN logo_image VARCHAR(255) DEFAULT ''", (aErr) => {
        if (aErr) console.error("Error adding logo_image column:", aErr);
        else console.log("Added logo_image column to contact_information table.");
      });
    }
  });

  // Update delivery_areas and CMS content in DB to Indiranagar
  connection.query("SELECT * FROM delivery_areas WHERE main_area LIKE '%Gachibowli%' OR main_area LIKE '%Hitech%' OR main_area LIKE '%Koramangala & HSR Layout%'", (dErr, dResult) => {
    if (!dErr && dResult && dResult.length > 0) {
      connection.query("TRUNCATE TABLE delivery_areas", () => {
        const bAreas = [
          ['HAL 2nd Stage & Defence Colony', '100 Feet Road, 12th Main, 100ft Rd, Doopanahalli', 'Shop now', '/#products', 1, 'active'],
          ['HAL 3rd Stage & Jeevan Bheema Nagar', 'New Tippasandra, Geethanjali Layout, Kodihalli', 'Shop now', '/#products', 2, 'active'],
          ['Domlur & EGL', 'Domlur Layout, Amarjyothi Layout, Wind Tunnel Road', 'Shop now', '/#products', 3, 'active'],
          ['Ulsoor & Cambridge Layout', 'Gupta Layout, Jogupalya, MG Road', 'Shop now', '/#products', 4, 'active'],
          ['CV Raman Nagar', 'Kaggadasapura, GM Palya, Malleshpalya', 'Shop now', '/#products', 5, 'active'],
          ['Koramangala & HSR Layout', '1st Block, 4th Block, HSR Layout Sectors', 'Shop now', '/#products', 6, 'active']
        ];
        connection.query("INSERT INTO delivery_areas (main_area, sub_areas, link_text, link_url, display_order, status) VALUES ?", [bAreas], (iErr) => {
          if (!iErr) console.log("Updated database delivery_areas to Indiranagar locations.");
        });
      });
    }
  });

  // Run updates to rename any existing Indiranagar/Bangalore/Bengaluru content to Indiranagar
  connection.query("UPDATE about_us SET title = REPLACE(REPLACE(REPLACE(title, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar'), description = REPLACE(REPLACE(REPLACE(description, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar')");
  connection.query("UPDATE why_choose_us SET title = REPLACE(REPLACE(REPLACE(title, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar'), description = REPLACE(REPLACE(REPLACE(description, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar')");
  connection.query("UPDATE footer_settings SET footer_text = REPLACE(REPLACE(REPLACE(REPLACE(footer_text, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar'), 'Koramangala', 'Indiranagar'), copyright_text = REPLACE(REPLACE(REPLACE(copyright_text, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar'), footer_logo_text = REPLACE(REPLACE(REPLACE(footer_logo_text, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar')");
  connection.query("UPDATE contact_information SET address = REPLACE(REPLACE(REPLACE(address, 'Indiranagar', 'Indiranagar'), 'Bangalore', 'Indiranagar'), 'Bengaluru', 'Indiranagar')");

  // Ensure whatsapp_settings table supports emojis
  connection.query("ALTER TABLE whatsapp_settings CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", (err) => {
    if (err) console.error("Error setting utf8mb4 on whatsapp_settings:", err);
  });

  // Ensure whatsapp_settings has a default row if empty
  connection.query("SELECT COUNT(*) as count FROM whatsapp_settings", (wErr, wResult) => {
    if (!wErr && wResult && wResult[0] && wResult[0].count === 0) {
      const defaultMsg = "Hi I Am Interested in your vape";
      const defaultTemplate = `━━━━━━━━━━━━━━━━━━━━
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
      connection.query(
        "INSERT INTO whatsapp_settings (business_number, default_message, custom_template) VALUES (?, ?, ?)",
        ['', defaultMsg, defaultTemplate],
        (iErr) => {
          if (iErr) console.error("Error seeding default whatsapp settings:", iErr);
          else console.log("Seeded default whatsapp settings.");
        }
      );
    }
  });
});

module.exports = connection;
