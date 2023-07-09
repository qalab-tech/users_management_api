const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const yaml = require('js-yaml');
const jwt = require('jsonwebtoken');
// const secretKey = process.env.MY_SECRET_KEY;

const pool = require('./db/db');
const router = express.Router();
const logger = require('../utils/logger');

// Load YAML config file

let config = null;

try {
  const fileContents = fs.readFileSync('./config/config.yaml', 'utf8');
  config = yaml.load(fileContents);
} catch (err) {
  console.error(err);
  process.exit(1);
}

// module.exports = config;

// Use config.jwt_secret instead of process.env.JWT_SECRET
// const token = jwt.sign({ userId: user.id }, config.jwt_secret, { expiresIn: '1h' });



//User login endpoint
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const client = await pool.connect();
    const result = await client.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    const user = result.rows[0];
    client.release();

    if (user) {
      // retrieve the user's salt and hashed password from the database
      const salt = user.salt;
      const hashedPasswordFromDb = user.password;

      // compare the input password with the hashed password in the database
      const isPasswordMatch = await bcrypt.compare(password, hashedPasswordFromDb);

      if (isPasswordMatch) {
        const token = jwt.sign({ userId: user.id }, config.jwt_secret, { expiresIn: '1h' });
        res.status(200).json({ token });
      } else {
        res.status(401).json({ error: 'Incorrect password' });
      }
      
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET All users
// GET All users with pagination
/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     description: Returns all users
 *     parameters:
 *       - name: page
 *         in: query
 *         description: Page number
 *         required: false
 *         schema:
 *           type: integer
 *           minimum: 1
 *       - name: pageSize
 *         in: query
 *         description: Number of items per page
 *         required: false
 *         schema:
 *           type: integer
 *           minimum: 1
 *     responses:
 *       200:
 *         description: Successful response
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 */
router.get('/users', async (req, res) => {
  const { page = 1, pageSize = 10 } = req.query;

  try {
    const offset = (page - 1) * pageSize;

    const countResult = await pool.query('SELECT COUNT(*) FROM users');
    const totalCount = parseInt(countResult.rows[0].count);

    const result = await pool.query(
      'SELECT id, username, email FROM users OFFSET $1 LIMIT $2',
      [offset, pageSize]
    );

    const users = result.rows.map(user => {
      const { id, username, email } = user;
      return { id, username, email };
    });

    res.json({
      page,
      pageSize,
      totalCount,
      totalPages: Math.ceil(totalCount / pageSize),
      users
    });

    logger.info('Successfully retrieved user data');
  } catch (err) {
    console.error(err);
    logger.error('An error occurred while fetching users');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// POST user
router.post('/users', async (req, res) => {
  const { username, email, password } = req.body;
  // generate a salt with 10 rounds of hashing
  const salt = await bcrypt.genSalt(10);
  // hash the password with the salt
  const hashedPassword = await bcrypt.hash(password, salt);
  try {
    logger.info(`Creating user with username: ${username} and email: ${email}`);
    // Check if user with the same email already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      logger.error(`User with email ${email} already exists`);
      return res.status(400).json({ error: 'User with this email already exists' });
    }
    // Check if user with the same username already exists
    const existingUsername = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUsername.rows.length > 0) {
      logger.error(`User with username ${username} already exists`);
      return res.status(400).json({ error: 'User with this username already exists' });
    }
    const result = await pool.query(
      'INSERT INTO users (username, email, password, salt) VALUES ($1, $2, $3, $4) RETURNING id, username, email',
      [username, email, hashedPassword, salt]
    );
    const user = result.rows[0];
    logger.info(`User with username ${username} and email ${email} has been created with id ${user.id}`);
    res.status(201).json(user);
  } catch (err) {
    logger.error(`Error creating user with username ${username} and email ${email}: ${err.message}`);
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



// PUT user
router.put('/user/:id', async (req, res) => {
  const { id } = req.params;
  const { username, email, password } = req.body;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authorization token is required' });
  }

  try {
    const decoded = jwt.verify(token, config.jwt_secret);
    if (decoded.userId !== parseInt(id)) {
      return res.status(403).json({ error: 'You are not authorized to update this user' });
    }

    const client = await pool.connect();
    // Check if user exists
    const checkUserExists = await client.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    if (checkUserExists.rows.length === 0) {
      logger.info(`User ${id} not found`);
      res.status(404).json({ error: 'User not found' });
    } else {
      const checkDuplicateUsername = await client.query(
        'SELECT * FROM users WHERE username = $1 AND id != $2',
        [username, id]
      );
      const checkDuplicateEmail = await client.query(
        'SELECT * FROM users WHERE email = $1 AND id != $2',
        [email, id]
      );
      if (checkDuplicateUsername.rows.length > 0) {
        logger.debug(`User ${id} - ${username} - Duplicate username`);
        res.status(409).json({ error: 'Username already exists' });
      } else if (checkDuplicateEmail.rows.length > 0) {
        logger.debug(`User ${id} - ${email} - Duplicate email`);
        res.status(409).json({ error: 'Email already exists' });
      } else {
        // generate a salt with 10 rounds of hashing
        const salt = await bcrypt.genSalt(10);
        // hash the password with the salt
        const hashedPassword = await bcrypt.hash(password, salt);
        const result = await client.query(
          'UPDATE users SET username = $1, email = $2, password=$3, salt=$4 WHERE id = $5 RETURNING id, username, email',
          [username, email, hashedPassword, salt, id]
        );
        const user = result.rows[0];
        client.release();
        logger.info(`User ${id} - ${username} - Updated successfully`);
        res.status(200).json(user);
      }
    }
  } catch (err) {
    logger.error(`User ${id} - ${err.message}`);
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// DELETE /user/<id>

router.delete('/user/:id', async (req, res) => {
  const { id } = req.params;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authorization token is required' });
  }

  try {
    const decoded = jwt.verify(token, config.jwt_secret);
    if (decoded.userId !== parseInt(id)) {
      return res.status(403).json({ error: 'You are not authorized to delete this user' });
    }

    const client = await pool.connect();
    const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
    const user = result.rows[0];
    client.release();

    if (user) {
      logger.info(`User with id ${id} has been deleted`);
      res.status(200).json({ success: 'User deleted' });
    } else {
      logger.error(`User with id ${id} not found`);
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    logger.error(`Error while deleting user with id ${id}: ${err}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



// GET /user/<id>
router.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const client = await pool.connect();
    const result = await client.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    const user = result.rows[0];
    client.release();
    if (user) {
      delete user.password; // remove password field
      delete user.salt; // removing password salt field
      logger.info(`Retrieved user with id ${userId}`);
      res.status(200).json(user);
    } else {
      logger.warn(`User with id ${userId} not found`);
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    logger.error(`Error retrieving user with id ${userId}: ${err.message}`);
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


module.exports = router;
