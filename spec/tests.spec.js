const { Passport } = require('../');

describe('Passport', () => {
  describe('check', () => {
    const superAdmin = new Passport({
      user_id: 1,
      user_type: 'superadmin',
    });

    const admin = new Passport({
      user_id: 56,
      user_type: 'admin',
      permissions: [PERMISSIONS.manage_users],
    });

    const customer = new Passport({
      user_type: 'customer',
      user_id: 166,
    });

    it('can check user id', () => {
      expect(
        customer
          .check()
          .isUser(166)
          .get()
      ).to.be.true;

      expect(
        admin
          .check()
          .isUser(144)
          .get()
      ).to.be.false;
    });

    it('can check roles', () => {
      expect(
        admin
          .check()
          .isAdmin()
          .get()
      ).to.be.true;

      expect(
        superAdmin
          .check()
          .isSuperAdmin()
          .get()
      ).to.be.true;
    });

    it('can form boolean expressions', () => {
      expect(
        admin
          .check()
          .isUser(32)
          .or()
          .canManageUsers()
          .get()
      ).to.be.true;

      expect(
        admin
          .check()
          .isUser(32)
          .and()
          .canManageUsers()
          .get()
      ).to.be.false;
      expect(
        admin
          .check()
          .isUser(32)
          .or()
          .isSuperAdmin()
          .get()
      ).to.be.false;
    });

    it('can form subexpressions', () => {
      expect(
        admin
          .check()
          .sub(check =>
            check
              .isUser(32)
              .or()
              .isAdmin()
          )
          .or(check =>
            check
              .isUser(56)
              .or()
              .isSuperAdmin()
          )
          .and()
          .canManageUsers()
          .get()
      ).to.be.true;
    });

    it('can assert', () => {
      expect(() => {
        customer
          .check()
          .can(PERMISSIONS.moderate_trollbox)
          .assert();
      }).to.throw(AccessForbiddenError);
    });
  });
});
