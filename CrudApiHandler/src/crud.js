require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const expressJwt = require('express-jwt');
const { expressjwt: expressJwt } = require("express-jwt");

class CrudApiHandler {
  constructor() {
    console.log(process.env.DB_HOST);
    this.connection = mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
    });

    this.app = express();

    const rateLimit = require("express-rate-limit");

    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
    });

    //  apply to all requests    
    this.app.use(limiter);
    this.app.use(express.json());
    this.app.use(this.handleSyntaxError);
     
    this.jwtMiddleware = expressJwt({
      secret: process.env.JWT_SECRET,
      algorithms: ["HS256"],
    }).unless({ path: ["/api/crud/authenticate"] });

    this.app.use(this.jwtMiddleware);
  }

  handleSyntaxError(err, req, res, next) {
    if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
      console.error("Bad JSON");
      return res
        .status(400)
        .send({ status: 400, message: "Corpo da requisição inválido." });
    }
    next();
  }

  start(port) {
    this.app.listen(port, () => {
      console.log(`Servidor iniciado na porta ${port}`);
    });
  }

  setupEndpoints() { 
    this.app.post("/api/crud/authenticate", this.authenticate.bind(this)); 
    
    // Protect the following routes with the JWT middleware
    this.app.use(this.jwtMiddleware);

    this.app.post(
      "/api/crud",
      body("tableName").custom((value) => /^[a-zA-Z0-9_]+$/.test(value)),
      body("fields").isObject(),
      this.createRecord.bind(this)
    );
    this.app.get(
      "/api/crud",
      body("tableName").custom((value) => /^[a-zA-Z0-9_]+$/.test(value)),
      body("fields").optional().isObject(),
      this.readRecords.bind(this)
    );
    this.app.put(
      "/api/crud",
      body("tableName").custom((value) => /^[a-zA-Z0-9_]+$/.test(value)),
      body("fields").isObject(),
      this.updateRecord.bind(this)
    );
    this.app.delete(
      "/api/crud",
      body("tableName").custom((value) => /^[a-zA-Z0-9_]+$/.test(value)),
      body("fields").isObject(),
      this.deleteRecord.bind(this)
    );
  }

  authenticate(req, res) {
    const { username, password } = req.body;

    // Query to fetch the user by username
    const query = `SELECT * FROM bot_users WHERE name = ?`;

    this.connection.query(query, [username], (error, results) => {
      if (error)
        return this.handleError(res, error, "Erro na busca do usuário");

      // Verify if a user was found and compare the provided password with the stored hashed password
      if (
        results.length > 0 &&
        bcrypt.compareSync(password, results[0].password)
      ) {
        const token = jwt.sign({ username }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });
        res.json({ token });
      } else {
        res.status(401).send("Autenticação falhou");
      }
    });
  }

  createRecord(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let { tableName, fields } = req.body;

    // Check if the password field is present
    if (!fields.password) {
      return res.status(400).json({ error: "Password field is required" });
    }

    const hashedPassword = bcrypt.hashSync(fields.password, 10); // Hash the password
    fields.password = hashedPassword; // Replace the plaintext password with the hashed password

    tableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");
    const query = `INSERT INTO ${tableName} SET ?`;

    this.connection.query(query, fields, (error, results) => {
      if (error) return this.handleError(res, error, "Erro na inserção");
      res.status(201).json({ message: "Registro criado com sucesso" });
    });
  }

  readRecords(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let { tableName, fields } = req.body;
    tableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");
    let query = `SELECT * FROM ${tableName}`;

    if (fields && Object.keys(fields).length > 0) {
      const conditions = Object.keys(fields)
        .map((key) => `${key} = ${mysql.escape(fields[key])}`)
        .join(" AND ");
      query += ` WHERE ${conditions}`;
    }

    this.connection.query(query, (error, results) => {
      if (error) return this.handleError(res, error, "Error fetching records");
      res.status(200).json(results);
    });
  }

  updateRecord(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let { tableName, fields } = req.body;
    tableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");
    const key = Object.keys(fields)[0];
    const value = fields[key];
    const query = `UPDATE ${tableName} SET ? WHERE ${key} = ?`;

    this.connection.query(query, [fields, value], (error, results) => {
      if (error) return this.handleError(res, error, "Error updating record");
      res.status(200).json({ message: "Record updated successfully" });
    });
  }

  deleteRecord(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let { tableName, fields } = req.body;
    tableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");
    const key = Object.keys(fields)[0];
    const value = fields[key];
    const query = `DELETE FROM ${tableName} WHERE ${key} = ?`;

    this.connection.query(query, [value], (error, results) => {
      if (error) return this.handleError(res, error, "Error deleting record");
      res.status(200).json({ message: "Record deleted successfully" });
    });
  }

  handleError(res, error, message) {
    console.error(message, error.sqlMessage || error.message);
    res.status(500).json({ error: error.sqlMessage || error.message });
  }
}

module.exports = CrudApiHandler;
