const jwt = require('jsonwebtoken');
const Session = require('../models/Session');
const { handleAuthenticationError } = require('../utils/errorHandling');

const authenticateUser = async (req, res, next) => {
  const token = req.header('Authorization').replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const session = await Session.findOne({ _id: decoded._id, 'tokens.token': token });

    if (!session) {
      throw new Error();
    }

    // Check if the token has expired
    const currentTimestamp = new Date().getTime();
    if (decoded.exp * 1000 < currentTimestamp) {
      throw new Error('Token has expired.');
    }

    req.session = session;
    req.token = token;
    next();
  } catch (error) {
    handleAuthenticationError(res, 'Authentication failed.');
  }
};

module.exports = authenticateUser;
