require('dotenv').config()
const express = require('express');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const app = express();
const swaggerSetup = require('./swagger');

const httpLogger = (req, res, next) => {
  console.log(`${req.method} ${req.url} - ${new Date()}`);
  next();
};

// add HTTP request/response logger middleware
app.use(httpLogger);

// create a write stream to the access log file
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'logs', 'access.log'),
  { flags: 'a' }
);

// set up the morgan middleware with a custom format string
app.use(
  morgan(
    'combined',
    {
      stream: accessLogStream,
      // skip: (req, res) => res.statusCode < 400 // skip logging successful requests
    }
  )
);

const port = 3000;

const usersRouter = require('./src/users');

// parse JSON request body
app.use(express.json());

// register user-related endpoints
app.use('/', usersRouter);

// Initialize Swagger documentation
swaggerSetup(app);

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});


// - config/
//   - config.yaml
// - db/
//   - db.js
// - controllers/
//   - users.js
//   - user.js
// - middleware/
//   - jsonParser.js
// - index.js
