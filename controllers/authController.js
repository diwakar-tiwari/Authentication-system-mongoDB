const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Session = require('../models/Session');
// const { handleAuthenticationError } = require('../utils/errorHandling');

const register = async (req, res) => {
  try {
    // Validate and create a new user
    const { email, password, name } = req.body;

    // Check if the email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user
    const user = new User({ email, password: hashedPassword, name });
    await user.save();

    // Create a new session and return a token
    const session = new Session({ userId: user._id });
    const token = jwt.sign({ _id: session._id.toString() }, process.env.JWT_SECRET, { expiresIn: '24h' });
    session.tokens = [{ token }];
    await session.save();

    res.status(201).json({ token });
  } catch (error) {
    // Handle registration error
    console.error(error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

const login = async (req, res) => {
  try {
    // Validate user credentials and return a token
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const session = new Session({ userId: user._id });
    const token = jwt.sign({ _id: session._id.toString() }, process.env.JWT_SECRET, { expiresIn: '24h' });
    session.tokens = [{ token }];
    await session.save();

    res.json({ token });
  } catch (error) {
    // Handle login error
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
};

const logout = async (req, res) => {
  try {
    // Logout the user by removing the token from the session
    const session = req.session;
    session.tokens = session.tokens.filter((tokenObj) => tokenObj.token !== req.token);
    
    // Save the updated session (assuming your Session model supports .save())
    await session.save();

    res.json({ message: 'Logout successful' });
  } catch (error) {
    // Handle logout error
    console.error(error);
    res.status(500).json({ error: 'Logout failed' });
  }
};


const refreshToken = async (req, res) => {
  try {
    // Refresh the user's token
    const oldToken = req.header('Authorization').replace('Bearer ', '');

    const decoded = jwt.verify(oldToken, process.env.JWT_SECRET);
    const session = await Session.findOne({ _id: decoded._id, 'tokens.token': oldToken });

    if (!session) {
      throw new Error();
    }

    // Check if the token  expired
    const currentTimestamp = new Date().getTime();
    if (decoded.exp * 1000 < currentTimestamp) {
      throw new Error('Token has expired.');
    }

    // Create a new token with an extended expiration time
    const newToken = jwt.sign({ _id: session._id.toString() }, process.env.JWT_SECRET, {
      expiresIn: '24h', 
    });

    // Update the session with the new token
    session.tokens = session.tokens.filter((token) => token.token !== oldToken);
    session.tokens.push({ token: newToken });
    await session.save();

    res.send({ token: newToken });
  } catch (error) {
    // Handle token refresh error
    console.error(error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
};

module.exports = {
  register,
  login,
  logout,
  refreshToken,
};
