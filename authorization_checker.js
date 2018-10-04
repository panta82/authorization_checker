const { PERMISSIONS } = require('./types');

const AUTHORIZATION_CHECKER_OPS = {
  and: 'and',
  or: 'or',
};

/**
 * @callback AuthorizationCheckerExecutor
 * @param {AuthorizationChecker} checker
 * @returns AuthorizationChecker
 */

/**
 * Builder that checks authorization rules against a passport
 * TODO: Sigh, we probably don't need this. Keep it around for a bit, but probably get rid of :(
 */
class AuthorizationChecker {
  constructor(passport, parent = null, op = null) {
    /** @type {Passport} */
    this._passport = passport;

    /** @type {AuthorizationChecker} */
    this._parent = parent;
    this._op = op;

    this._value = undefined;
  }

  _hasValue() {
    return this._value !== undefined;
  }

  _subExpression(op, executor) {
    const child = this._hasValue() ? new AuthorizationChecker(this._passport, this, op) : this;

    if (executor) {
      const executorChecker = new AuthorizationChecker(this._passport);
      child._value = executor.bind(executorChecker, executorChecker);
    }

    return child;
  }

  /**
   * Set value to be a subexpression
   * @param {AuthorizationCheckerExecutor} executor
   * @return {AuthorizationChecker}
   */
  sub(executor) {
    return this._subExpression(AUTHORIZATION_CHECKER_OPS.and, executor);
  }

  /**
   * @param {AuthorizationCheckerExecutor} [executor]
   * @return {AuthorizationChecker}
   */
  and(executor = undefined) {
    return this._subExpression(AUTHORIZATION_CHECKER_OPS.and, executor);
  }

  /**
   * @param {AuthorizationCheckerExecutor} [executor]
   * @return {AuthorizationChecker}
   */
  or(executor = undefined) {
    return this._subExpression(AUTHORIZATION_CHECKER_OPS.or, executor);
  }

  /**
   * Checks if the passport owner is a specific user
   * @return {AuthorizationChecker}
   */
  isUser(userId) {
    if (this._hasValue()) {
      return this.and().isUser(userId);
    }

    this._value = this._passport.user_id === userId;
    return this;
  }

  /**
   * @return {AuthorizationChecker}
   */
  isAdmin() {
    if (this._hasValue()) {
      return this.and().isAdmin();
    }

    this._value = this._passport.isAdmin;
    return this;
  }

  /**
   * @return {AuthorizationChecker}
   */
  isSuperAdmin() {
    if (this._hasValue()) {
      return this.and().isSuperAdmin();
    }

    this._value = this._passport.isSuperAdmin;
    return this;
  }

  /**
   * @return {AuthorizationChecker}
   */
  can(permission) {
    if (this._hasValue()) {
      return this.and().has(permission);
    }

    this._value = this._passport.can(permission);
    return this;
  }

  /**
   * @return {AuthorizationChecker}
   */
  canManageUsers() {
    return this.can(PERMISSIONS.manage_users);
  }

  /**
   * @return {AuthorizationChecker}
   */
  canManageProducts() {
    return this.can(PERMISSIONS.manage_products);
  }

  /**
   * Executes all the checks and returns true or false
   * @return {Boolean}
   */
  get() {
    let result;
    if (this._value === undefined) {
      this._hasValue = true;
    } else if (typeof this._value === 'function') {
      result = this._value();
      if (result.get) {
        result = result.get();
      }
    } else {
      result = this._value;
    }

    if (this._parent && this._op) {
      const parentResult = this._parent.get();
      switch (this._op) {
        case AUTHORIZATION_CHECKER_OPS.and:
          result = result && parentResult;
          break;
        case AUTHORIZATION_CHECKER_OPS.or:
          result = result || parentResult;
          break;
      }
    }
    return result;
  }

  /**
   * Executes all the checks and throws an AccessForbiddenError if false
   */
  assert() {
    const result = this.get();
    if (result === false) {
      throw new AccessForbiddenError(`Access to requested resource is denied`);
    }
  }
}

class AccessForbiddenError extends Error {
  constructor(message) {
    super(message);
    this.code = 403;
  }
}

module.exports = {
  AuthorizationChecker,
  AccessForbiddenError,
};
