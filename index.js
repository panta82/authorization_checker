const { AuthorizationChecker, AccessForbiddenError } = require('./authorization_checker');
const { Passport } = require('./passport');

module.exports = {
  AuthorizationChecker,
  AccessForbiddenError,
  Passport,
};
