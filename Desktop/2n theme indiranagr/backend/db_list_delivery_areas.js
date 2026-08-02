const mysql = require("mysql2");
require("dotenv").config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect((err) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  connection.query("SELECT * FROM delivery_areas", (err, rows) => {
    if (err) {
      console.error(err);
    } else {
      console.log("Delivery Areas:");
      console.log(JSON.stringify(rows, null, 2));
    }
    connection.end();
  });
});
