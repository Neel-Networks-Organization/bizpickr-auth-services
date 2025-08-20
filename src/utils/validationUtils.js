/**
 * Essential Validation Utilities for authService
 *
 * Purpose: Basic input validation for user authentication
 * Features:
 * - Email validation
 * - Password validation
 * - Basic input sanitization
 */

import { safeLogger } from '../config/logger.js';

/**
 * Basic Email Validation
 */
export const validateEmail = email => {
  try {
    if (!email) {
      return { isValid: false, errors: ['Email is required'] };
    }

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return { isValid: false, errors: ['Invalid email format'] };
    }

    // Check email length
    if (email.length > 254) {
      return { isValid: false, errors: ['Email too long'] };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('Email validation error', { error: error.message });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Basic Password Validation
 */
export const validatePassword = password => {
  try {
    if (!password) {
      return { isValid: false, errors: ['Password is required'] };
    }

    const errors = [];

    // Length validation
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    if (password.length > 128) {
      errors.push('Password must not exceed 128 characters');
    }

    // Basic complexity requirements
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (errors.length > 0) {
      return { isValid: false, errors };
    }

    return { isValid: true, errors: [] };
  } catch (error) {
    safeLogger.error('Password validation error', { error: error.message });
    return { isValid: false, errors: [error.message] };
  }
};

/**
 * Basic Input Sanitization
 */
export const sanitizeInput = input => {
  if (typeof input !== 'string') {
    return input;
  }

  return input
    .trim()
    .replace(/[<>]/g, '') // Remove < and >
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, ''); // Remove event handlers
};

/**
 * Validate Required Fields
 */
export const validateRequired = (data, requiredFields) => {
  const errors = [];

  for (const field of requiredFields) {
    if (
      !data[field] ||
      (typeof data[field] === 'string' && data[field].trim() === '')
    ) {
      errors.push(`${field} is required`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

/**
 * Validate Object ID (MongoDB)
 */
export const validateObjectId = id => {
  if (!id) {
    return { isValid: false, errors: ['ID is required'] };
  }

  const objectIdRegex = /^[0-9a-fA-F]{24}$/;
  if (!objectIdRegex.test(id)) {
    return { isValid: false, errors: ['Invalid ID format'] };
  }

  return { isValid: true, errors: [] };
};

/**
 * Validate UUID
 */
export const validateUUID = uuid => {
  if (!uuid) {
    return { isValid: false, errors: ['UUID is required'] };
  }

  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(uuid)) {
    return { isValid: false, errors: ['Invalid UUID format'] };
  }

  return { isValid: true, errors: [] };
};

/**
 * Validate Phone Number
 */
export const validatePhoneNumber = phone => {
  if (!phone) {
    return { isValid: false, errors: ['Phone number is required'] };
  }

  // Basic phone validation (allows +, numbers, spaces, hyphens, parentheses)
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  if (!phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''))) {
    return { isValid: false, errors: ['Invalid phone number format'] };
  }

  return { isValid: true, errors: [] };
};

/**
 * Validate Date
 */
export const validateDate = date => {
  if (!date) {
    return { isValid: false, errors: ['Date is required'] };
  }

  const dateObj = new Date(date);
  if (isNaN(dateObj.getTime())) {
    return { isValid: false, errors: ['Invalid date format'] };
  }

  return { isValid: true, errors: [] };
};

/**
 * Validate Numeric Range
 */
export const validateNumericRange = (value, min, max) => {
  if (value === null || value === undefined) {
    return { isValid: false, errors: ['Value is required'] };
  }

  const num = Number(value);
  if (isNaN(num)) {
    return { isValid: false, errors: ['Value must be a number'] };
  }

  if (num < min) {
    return { isValid: false, errors: [`Value must be at least ${min}`] };
  }

  if (num > max) {
    return { isValid: false, errors: [`Value must not exceed ${max}`] };
  }

  return { isValid: true, errors: [] };
};

export default {
  validateEmail,
  validatePassword,
  sanitizeInput,
  validateRequired,
  validateObjectId,
  validateUUID,
  validatePhoneNumber,
  validateDate,
  validateNumericRange,
};
