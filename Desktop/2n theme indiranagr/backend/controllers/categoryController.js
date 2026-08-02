const db = require("../config/db");

// Create Category
const createCategory = (req, res) => {
  const { category_name, slug, description, status } = req.body;

  const sql =
    "INSERT INTO categories (category_name, slug, description, status) VALUES (?, ?, ?, ?)";

  db.query(
    sql,
    [category_name, slug, description, status == 1 ? 'active' : 'inactive'],
    (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      res.status(201).json({
        success: true,
        message: "Category Created Successfully",
      });
    }
  );
};

// Get All Categories
const getCategories = (req, res) => {
  db.query(
    "SELECT * FROM categories ORDER BY id DESC",
    (err, results) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      const formattedResults = results.map(r => ({
        ...r,
        status: r.status === 'active' ? 1 : 0
      }));

      res.json({
        success: true,
        categories: formattedResults,
      });
    }
  );
};

// Get Single Category
const getCategoryById = (req, res) => {
  const { id } = req.params;

  db.query(
    "SELECT * FROM categories WHERE id = ?",
    [id],
    (err, results) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Category Not Found",
        });
      }

      res.json({
        success: true,
        category: results[0],
      });
    }
  );
};

// Update Category
const updateCategory = (req, res) => {
  const { id } = req.params;
  const { category_name, slug, description, status } = req.body;

  const sql = `
    UPDATE categories
    SET category_name = ?, slug = ?, description = ?, status = ?
    WHERE id = ?
  `;

  db.query(
    sql,
    [category_name, slug, description, status == 1 ? 'active' : 'inactive', id],
    (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      res.json({
        success: true,
        message: "Category Updated Successfully",
      });
    }
  );
};

// Delete Category
const deleteCategory = (req, res) => {
  const { id } = req.params;

  db.query(
    "DELETE FROM categories WHERE id = ?",
    [id],
    (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      res.json({
        success: true,
        message: "Category Deleted Successfully",
      });
    }
  );
};

module.exports = {
  createCategory,
  getCategories,
  getCategoryById,
  updateCategory,
  deleteCategory,
};
