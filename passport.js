const { USER_TYPES } = require('./types');
const { AuthorizationChecker } = require('./authorization_checker');

class Passport {
  constructor(/** Passport */ source) {
    this.id = undefined;
    this.user_id = undefined;
    this.user_type = undefined;
    this.permissions = undefined;
    this.timestamp = undefined;

    Object.assign(this, source);
  }

  get isSuperAdmin() {
    return this.user_type === USER_TYPES.superadmin;
  }

  get isAdmin() {
    return this.user_type === USER_TYPES.admin;
  }

  /**
   * @param {PERMISSIONS} permission
   */
  can(permission) {
    return this.isSuperAdmin || (this.isAdmin && this.permissions.includes(permission));
  }

  /**
   * @return {AuthorizationChecker}
   */
  check() {
    return new AuthorizationChecker(this);
  }
}

module.exports = {
  Passport,
};
