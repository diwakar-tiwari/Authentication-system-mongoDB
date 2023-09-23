const handleAuthenticationError = (res, message) => {
  return res.status(401).send({ error: message });
};

module.exports = {
  handleAuthenticationError,
};
