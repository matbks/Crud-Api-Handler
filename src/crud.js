require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { expressjwt: expressJwt } = require("express-jwt");

console.log("Configurações de conexão com o banco de dados:");
console.log("Host:", process.env.DB_HOST);
console.log("Usuário:", process.env.DB_USER);
console.log("Senha:", process.env.DB_PASSWORD);
console.log("Database:", process.env.DB_DATABASE);

function generateHashedPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

class CrudApiHandler {
  constructor() {
    console.log(process.env.DB_HOST);
    this.connection = mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
      port: process.env.PORT
    });

    this.app = express();

    const rateLimit = require("express-rate-limit");

    const limiter = rateLimit({
      
      max: process.env.ENV = 'development' ? 200 : 100, // Número de chamadas
      windowMs: 15 * 60 * 1000, // 15 min

    });

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
      return res.status(400).send({ status: 400, message: "Corpo da requisição inválido." });
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
    const query = `SELECT * FROM users WHERE name = ?`;

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

      // Move o console.log dos resultados aqui
      console.log("Resultados da consulta de autenticação:", results);
    });
  }

  createRecord(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { tableName, fields } = req.body;

    if (tableName === 'users' && fields && fields.password) {
      fields.password = bcrypt.hashSync(fields.password, 10);
    }

    const query = `INSERT INTO ?? SET ?`;
    const values = [tableName, fields];

    this.connection.query(query, values, (error, results) => {
      if (error) return this.handleError(res, error, "Erro na inserção");
      res.status(201).json({ message: "Registro criado com sucesso" });
    });
  }

  // readRecords(req, res) {
  //   const errors = validationResult(req);
  //   if (!errors.isEmpty()) {
  //     return res.status(400).json({ errors: errors.array() });
  //   }

  //   let tableName = req.query.tableName; // Altere const para let

  //   console.log("tableName:", tableName);

  //   let query = `SELECT * FROM ??`;
  //   const values = [tableName];

  //   this.connection.query(query, values, (error, results) => {
  //     if (error) return this.handleError(res, error, "Erro na busca dos registros");
  //     res.json(results);
  //   });
  // }
  readRecords(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let tableName = req.query.tableName;
    let fields = req.query.fields || {};

    console.log("tableName:", tableName);
    console.log("fields:", fields);

    let query = `SELECT * FROM ??`;
    let values = [tableName];

    // Verifica se há campos para filtrar e constrói a cláusula WHERE
    if (Object.keys(fields).length > 0) {
      let whereClause = [];
      Object.keys(fields).forEach(field => {
        whereClause.push(mysql.escapeId(field) + ' = ' + mysql.escape(fields[field]));
      });
      query += ' WHERE ' + whereClause.join(' AND ');
    }

    this.connection.query(query, values, (error, results) => {
      if (error) return this.handleError(res, error, "Erro na busca dos registros");
      res.json(results);
    });
  }

  updateRecord(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { tableName, fields } = req.body;

    // Replacing tableName with a safe variable
    const safeTableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");

    // SQL Query - UPSERT operation (INSERT ... ON DUPLICATE KEY UPDATE)
    const query = `INSERT INTO ${safeTableName} SET ? ON DUPLICATE KEY UPDATE ?`;

    // Execute query with provided fields
    this.connection.query(query, [fields, fields], (error, results) => {
      if (error) return this.handleError(res, error, "Error handling record");

      // Determine if a new record was inserted or an existing one was updated
      if (results.insertId) {
        return res.status(201).json({ message: "New record created successfully", insertId: results.insertId });
      } else if (results.affectedRows) {
        return res.status(200).json({ message: "Record updated successfully" });
      } else {
        return res.status(404).json({ message: "No record found to update, and no new record was created" });
      }
    });
  }



  // deleteRecord(req, res) {

  //   const errors = validationResult(req);

  //   if (!errors.isEmpty()) {
  //     return res.status(400).json({ errors: errors.array() });
  //   }

  //   let { tableName, fields } = req.body;
  //   tableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");
  //   const key = Object.keys(fields)[0];
  //   const value = fields[key];
  //   const query = `DELETE FROM ${tableName} WHERE ${key} = ?`;

  //   this.connection.query(query, [value], (error, results) => {
  //     if (error) return this.handleError(res, error, "Error deleting record");
  //     res.status(200).json({ message: "Record deleted successfully" });
  //   });
  // }

  deleteRecord(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    let { tableName, fields } = req.body;
    tableName = tableName.replace(/[^a-zA-Z0-9_]/g, "");
  
    // Construa a cláusula WHERE dinamicamente
    const whereClauses = Object.entries(fields).map(([key, value]) => {
      return `${mysql.escapeId(key)} = ${mysql.escape(value)}`;
    });
  
    if (whereClauses.length === 0) {
      return res.status(400).json({ error: 'No fields provided for deletion' });
    }
  
    const query = `DELETE FROM ${tableName} WHERE ` + whereClauses.join(' AND ');
  
    this.connection.query(query, (error, results) => {
      if (error) return this.handleError(res, error, "Error deleting record");
      if (results.affectedRows > 0) {
        res.status(200).json({ message: "Record deleted successfully" });
      } else {
        res.status(404).json({ message: "Record not found" });
      }
    });
  }
  

  handleError(res, error, message) {
    console.error(message, error.sqlMessage || error.message);
    res.status(500).json({ error: error.sqlMessage || error.message });
  }
}

module.exports = CrudApiHandler;