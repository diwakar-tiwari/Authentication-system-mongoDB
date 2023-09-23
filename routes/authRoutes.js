const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authenticateUser = require('../middleware/authenticationMiddleware');

// POST route for user registration
router.post('/register', authController.register);

// POST route for user login
router.post('/login', authController.login);

// GET route for user logout
router.get('/logout', authenticateUser, authController.logout);

// POST route for token refresh
router.post('/refresh-token', authenticateUser, authController.refreshToken);

module.exports = router;
