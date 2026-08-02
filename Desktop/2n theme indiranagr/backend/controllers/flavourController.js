const db = require("../config/db");

// Create Flavour
const createFlavour = (req, res) => {
  const { flavour_name, slug } = req.body;

  const sql =
    "INSERT INTO flavours (flavour_name, slug) VALUES (?, ?)";

  db.query(sql, [flavour_name, slug], (err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: err.message,
      });
    }

    res.status(201).json({
      success: true,
      message: "Flavour Created Successfully",
    });
  });
};

// Get All Flavours
const getFlavours = (req, res) => {
  db.query(
    "SELECT * FROM flavours ORDER BY id DESC",
    (err, results) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      res.json({
        success: true,
        flavours: results,
      });
    }
  );
};

// Get Single Flavour
const getFlavourById = (req, res) => {
  const { id } = req.params;

  db.query(
    "SELECT * FROM flavours WHERE id = ?",
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
          message: "Flavour Not Found",
        });
      }

      res.json({
        success: true,
        flavour: results[0],
      });
    }
  );
};

// Update Flavour
const updateFlavour = (req, res) => {
  const { id } = req.params;
  const { flavour_name, slug, status } = req.body;

  const sql = `
    UPDATE flavours
    SET flavour_name = ?, slug = ?, status = ?
    WHERE id = ?
  `;

  db.query(
    sql,
    [flavour_name, slug, status, id],
    (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: err.message,
        });
      }

      res.json({
        success: true,
        message: "Flavour Updated Successfully",
      });
    }
  );
};

// Delete Flavour
const deleteFlavour = (req, res) => {
  const { id } = req.params;

  db.query(
    "DELETE FROM flavours WHERE id = ?",
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
        message: "Flavour Deleted Successfully",
      });
    }
  );
};

module.exports = {
  createFlavour,
  getFlavours,
  getFlavourById,
  updateFlavour,
  deleteFlavour,
};
