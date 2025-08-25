// authService/src/models/index.model.js
import sequelize from '../db/index.js';
import { AuthUser as User } from './authUser.model.js';
import Session from './session.model.js';
import UserActivity from './userActivity.model.js';
import AuditLog from './auditLog.model.js';
import PasswordReset from './passwordReset.model.js';
import EmailVerification from './emailVerification.model.js';

// User Associations
User.hasMany(Session, {
  foreignKey: 'userId',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE',
  as: 'sessions',
});

Session.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user',
});

User.hasMany(PasswordReset, {
  foreignKey: 'userId',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE',
  as: 'passwordResets',
});

PasswordReset.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user',
});

User.hasMany(EmailVerification, {
  foreignKey: 'userId',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE',
  as: 'emailVerifications',
});

EmailVerification.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user',
});

// Export all models and sequelize instance
export { sequelize, User, Session, PasswordReset, EmailVerification };
// Export Mongoose models separately
export { UserActivity, AuditLog };

// Export default for backward compatibility
export default {
  sequelize,
  User,
  Session,
  UserActivity,
  AuditLog,
  PasswordReset,
  EmailVerification,
};
