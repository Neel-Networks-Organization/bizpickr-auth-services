/**
 * Basic Validators for Auth Service
 * Clean, focused validation functions
 */

/**
 * Validate signup data
 * @param {Object} data - Signup data
 * @returns {Array} Array of error messages
 */
export const validateSignupData = data => {
  const errors = [];

  if (!data.email || !data.email.includes('@')) {
    errors.push('Valid email is required');
  }
  if (!data.password || data.password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  if (!data.fullName || data.fullName.length < 2) {
    errors.push('Full name must be at least 2 characters long');
  }
  if (!data.type || !['individual', 'company'].includes(data.type)) {
    errors.push('Valid user type is required');
  }
  if (!data.acceptTerms) {
    errors.push('Terms acceptance is required');
  }

  return errors;
};

/**
 * Validate login data
 * @param {Object} data - Login data
 * @returns {Array} Array of error messages
 */
export const validateLoginData = data => {
  const errors = [];

  if (!data.email || !data.email.includes('@')) {
    errors.push('Valid email is required');
  }
  if (!data.password) {
    errors.push('Password is required');
  }

  return errors;
};

/**
 * Validate password change data
 * @param {Object} data - Password change data
 * @returns {Array} Array of error messages
 */
export const validatePasswordChange = data => {
  const errors = [];
  if (!data.currentPassword) errors.push('Current password is required');
  if (!data.newPassword || data.newPassword.length < 8) {
    errors.push('New password must be at least 8 characters long');
  }
  return errors;
};

/**
 * Validate password reset data
 * @param {Object} data - Password reset data
 * @returns {Array} Array of error messages
 */
export const validatePasswordReset = data => {
  const errors = [];
  if (!data.token) errors.push('Reset token is required');
  if (!data.newPassword || data.newPassword.length < 8) {
    errors.push('New password must be at least 8 characters long');
  }
  return errors;
};

/**
 * Validate profile update data
 * @param {Object} data - Profile update data
 * @returns {Array} Array of error messages
 */
export const validateProfileUpdate = data => {
  const errors = [];
  if (data.fullName && data.fullName.length < 2) {
    errors.push('Full name must be at least 2 characters long');
  }
  if (data.bio && data.bio.length > 500) {
    errors.push('Bio must not exceed 500 characters');
  }
  if (data.avatar && !data.avatar.includes('http')) {
    errors.push('Avatar must be a valid URL');
  }
  return errors;
};

export default {
  validateSignupData,
  validateLoginData,
  validatePasswordChange,
  validatePasswordReset,
  validateProfileUpdate,
};
