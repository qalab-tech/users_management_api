const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  swaggerDefinition: {
    info: {
      title: 'User Management API',
      version: '1.1.1',
      description: 'API documentation',
    },
  },
  apis: ['./src/users.js'], // Path to the API routes files
};

const specs = swaggerJSDoc(options);

module.exports = app => {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));
};
