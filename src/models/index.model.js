// authService/src/models/index.model.js
import sequelize from '../db/index.js';
import AuthUser from './authUser.model.js';
import Session from './session.model.js';
import UserActivity from './userActivity.model.js';
import AuditLog from './auditLog.model.js';
import PasswordReset from './passwordReset.model.js';
import EmailVerification from './emailVerification.model.js';

// AuthUser Associations
AuthUser.hasMany(Session, {
  foreignKey: 'userId',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE',
  as: 'sessions',
});

Session.belongsTo(AuthUser, {
  foreignKey: 'userId',
  as: 'user',
});

AuthUser.hasMany(PasswordReset, {
  foreignKey: 'userId',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE',
  as: 'passwordResets',
});

PasswordReset.belongsTo(AuthUser, {
  foreignKey: 'userId',
  as: 'user',
});

AuthUser.hasMany(EmailVerification, {
  foreignKey: 'userId',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE',
  as: 'emailVerifications',
});

EmailVerification.belongsTo(AuthUser, {
  foreignKey: 'userId',
  as: 'user',
});

// Export all models and sequelize instance (Sequelize models only)
export { sequelize, AuthUser, Session, PasswordReset, EmailVerification };
// Export Mongoose models separately
export { UserActivity, AuditLog };

// Export default for backward compatibility
export default {
  sequelize,
  AuthUser,
  Session,
  UserActivity,
  AuditLog,
  PasswordReset,
  EmailVerification,
};
