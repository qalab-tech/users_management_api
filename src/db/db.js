const fs = require('fs');
const yaml = require('yaml');
const config = yaml.parse(fs.readFileSync('./config/config.yaml', 'utf8'));
const { Pool } = require('pg');

const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  database: config.db.database,
  user: config.db.user,
  password: config.db.password,
});

module.exports = pool;
