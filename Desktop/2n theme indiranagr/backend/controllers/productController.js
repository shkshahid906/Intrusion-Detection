const db = require("../config/db");
const fs = require("fs");
const path = require("path");

// Create Product
const createProduct = (req, res) => {
  const {
    name,
    slug,
    category_id,
    price,
    mrp,
    stock,
    sales_count,
    short_description,
    description,
    featured,
    status,
    seo_title,
    seo_description,
    seo_keywords,
    nicotine_strength
  } = req.body;

  const primaryImage = req.files && req.files['primary_image'] ? `/uploads/products/${req.files['primary_image'][0].filename}` : null;

  const sql = `
    INSERT INTO products 
    (product_name, slug, category_id, price, mrp, stock, sales_count, short_description, description, featured, status, seo_title, seo_description, seo_keywords, nicotine_strength, primary_image) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [
      name, slug, category_id || null, price || 0, mrp || 0, stock || 0, sales_count || 0, short_description || "", description || "",
      featured == 1 ? "yes" : "no", status == 1 ? "active" : "inactive", seo_title || "", seo_description || "", seo_keywords || "", nicotine_strength || "", primaryImage
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({ success: false, error: err.message });
      }

      const productId = result.insertId;

      // Handle Gallery Images
      if (req.files && req.files['images'] && req.files['images'].length > 0) {
        const imageValues = req.files['images'].map((file, index) => [
          productId,
          `/uploads/products/${file.filename}`,
          index, // display_order
        ]);

        db.query(
          "INSERT INTO product_images (product_id, image_path, display_order) VALUES ?",
          [imageValues],
          (iErr) => {
            if (iErr) console.error("Image upload mapping error:", iErr);
          }
        );
      }

      res.status(201).json({
        success: true,
        message: "Product Created Successfully",
        productId,
      });
    }
  );
};

// Get All Products
const getProducts = (req, res) => {
  const sql = `
    SELECT p.*, p.product_name as name, c.category_name, c.slug as category_slug
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    ORDER BY p.id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ success: false, error: err.message });
    }

    // Map enum values back to 1/0 for the frontend
    const formattedResults = results.map(r => ({
      ...r,
      status: r.status === 'active' ? 1 : 0,
      featured: r.featured === 'yes' ? 1 : 0
    }));
    
    // Fetch all flavours to attach to products
    db.query("SELECT * FROM product_flavours", (fErr, fResults) => {
      if (fErr) {
        return res.json({
          success: true,
          products: formattedResults,
        });
      }
      
      const finalProducts = formattedResults.map(p => ({
        ...p,
        flavours: fResults.filter(f => f.product_id === p.id)
      }));

      res.json({
        success: true,
        products: finalProducts,
      });
    });
  });
};

// Get Single Product
const getProductById = (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT p.*, p.product_name as name, c.category_name, c.slug as category_slug 
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.slug = ? OR p.id = ?
  `;

  db.query(sql, [id, id], (err, productResults) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    if (productResults.length === 0) return res.status(404).json({ success: false, message: "Product not found" });

    const product = productResults[0];
    // Map enum values back to 1/0 for the frontend
    product.status = product.status === 'active' ? 1 : 0;
    product.featured = product.featured === 'yes' ? 1 : 0;

    db.query("SELECT * FROM product_images WHERE product_id = ? ORDER BY display_order ASC", [product.id], (imgErr, imgResults) => {
      if (imgErr) return res.status(500).json({ success: false, error: imgErr.message });
      
      product.images = imgResults;

      const flavourSql = `SELECT * FROM product_flavours WHERE product_id = ?`;
      db.query(flavourSql, [product.id], (fErr, fResults) => {
        if (fErr) return res.status(500).json({ success: false, error: fErr.message });
        
        product.flavours = fResults;
        
        res.json({
          success: true,
          product,
        });
      });
    });
  });
};

// Update Product
const updateProduct = (req, res) => {
  const { id } = req.params;
  const {
    name, slug, category_id, price, mrp, stock, sales_count, short_description, description,
    featured, status, seo_title, seo_description, seo_keywords, nicotine_strength
  } = req.body;

  let updateFields = [name, slug, category_id, price, mrp || 0, stock, sales_count || 0, short_description, description, featured == 1 ? "yes" : "no", status == 1 ? "active" : "inactive", seo_title, seo_description, seo_keywords, nicotine_strength || ""];
  let sql = `
    UPDATE products 
    SET product_name=?, slug=?, category_id=?, price=?, mrp=?, stock=?, sales_count=?, short_description=?, description=?, 
        featured=?, status=?, seo_title=?, seo_description=?, seo_keywords=?, nicotine_strength=?
  `;

  if (req.files && req.files['primary_image']) {
    sql += ", primary_image=?";
    updateFields.push(`/uploads/products/${req.files['primary_image'][0].filename}`);
  }

  sql += " WHERE id=?";
  updateFields.push(id);

  db.query(
    sql,
    updateFields,
    (err) => {
      if (err) return res.status(500).json({ success: false, error: err.message });

      // Handle New Gallery Images if any
      if (req.files && req.files['images'] && req.files['images'].length > 0) {
        db.query("SELECT IFNULL(MAX(display_order), -1) as max_order FROM product_images WHERE product_id = ?", [id], (orderErr, orderRes) => {
           let startOrder = 0;
           if (!orderErr && orderRes.length > 0) startOrder = orderRes[0].max_order + 1;
           
           const imageValues = req.files['images'].map((file, index) => [
              id,
              `/uploads/products/${file.filename}`,
              startOrder + index
           ]);
           
           db.query("INSERT INTO product_images (product_id, image_path, display_order) VALUES ?", [imageValues], (iErr) => {
             if (iErr) console.error("Image update mapping error:", iErr);
           });
        });
      }

      res.json({ success: true, message: "Product Updated Successfully" });
    }
  );
};

// Delete Product
const deleteProduct = (req, res) => {
  const { id } = req.params;

  // First, get images to delete files
  db.query("SELECT image_path FROM product_images WHERE product_id = ?", [id], (err, images) => {
    if (!err && images.length > 0) {
      images.forEach(img => {
        const filePath = path.join(__dirname, "..", img.image_path);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      });
    }

    // Delete product (cascades or delete manually)
    db.query("DELETE FROM product_images WHERE product_id = ?", [id], () => {
      db.query("DELETE FROM product_flavours WHERE product_id = ?", [id], () => {
        db.query("DELETE FROM products WHERE id = ?", [id], (delErr) => {
          if (delErr) return res.status(500).json({ success: false, error: delErr.message });
          res.json({ success: true, message: "Product Deleted Successfully" });
        });
      });
    });
  });
};

// Delete a single image
const deleteProductImage = (req, res) => {
  const { imageId } = req.params;
  
  db.query("SELECT image_path FROM product_images WHERE id = ?", [imageId], (err, results) => {
     if (err || results.length === 0) return res.status(404).json({ success: false, message: "Image not found" });
     
     const filePath = path.join(__dirname, "..", results[0].image_path);
     if (fs.existsSync(filePath)) {
       fs.unlinkSync(filePath);
     }
     
     db.query("DELETE FROM product_images WHERE id = ?", [imageId], (delErr) => {
        if (delErr) return res.status(500).json({ success: false, error: delErr.message });
        res.json({ success: true, message: "Image deleted successfully" });
     });
  });
};

// Get Product Images (Standalone)
const getProductImages = (req, res) => {
  const { id } = req.params;
  
  db.query("SELECT * FROM product_images WHERE product_id = ? ORDER BY display_order ASC", [id], (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    
    res.json({
      success: true,
      images: results,
    });
  });
};

// --- Product Flavour Mapping Standalone Endpoints ---

// Get Product Flavours
const getProductFlavours = (req, res) => {
  const { id } = req.params;
  const sql = `SELECT * FROM product_flavours WHERE product_id = ? ORDER BY id ASC`;
  db.query(sql, [id], (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, flavours: results });
  });
};

// Assign/Update Flavours (Bulk replace)
const updateProductFlavours = (req, res) => {
  const { id } = req.params;
  const { flavours } = req.body; // Array of { flavour_name, stock }
  
  if (!Array.isArray(flavours)) {
    return res.status(400).json({ success: false, message: "Flavours must be an array of objects" });
  }

  // Remove existing
  db.query("DELETE FROM product_flavours WHERE product_id = ?", [id], (delErr) => {
    if (delErr) return res.status(500).json({ success: false, error: delErr.message });
    
    if (flavours.length === 0) {
      return res.json({ success: true, message: "Flavours updated (cleared) successfully" });
    }

    // Insert new
    const flavourValues = flavours.map((f) => [id, f.flavour_name, f.stock || 0]);
    db.query("INSERT INTO product_flavours (product_id, flavour_name, stock) VALUES ?", [flavourValues], (fErr) => {
      if (fErr) return res.status(500).json({ success: false, error: fErr.message });
      res.json({ success: true, message: "Flavours assigned successfully" });
    });
  });
};

// Remove single flavour from product
const removeProductFlavour = (req, res) => {
  const { id, flavourId } = req.params;
  
  db.query("DELETE FROM product_flavours WHERE product_id = ? AND id = ?", [id, flavourId], (err) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, message: "Flavour removed from product successfully" });
  });
};

module.exports = {
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
};
