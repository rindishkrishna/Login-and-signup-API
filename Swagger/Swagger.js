const swaggerJsdoc = require('swagger-jsdoc');
const options = {
    swaggerDefinition: {
        info: {
            title: "Register-Login API Documentation",
            version: "1.0.0",
            description:
                "A documention of Backend API written in Nodejs.",
        },
        securityDefinitions: {
            Bearer: {
                "type": "apiKey",
                "name": "auth",
                "in": "header"
            },
        }
    },
    apis: ['./Routes/LoginRoute.js','./Routes/RegisterRoute.js']
};
const specs = swaggerJsdoc(options);
module.exports =specs;
