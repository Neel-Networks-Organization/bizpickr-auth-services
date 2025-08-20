/**
 * Utils Index - Central Export for All Utility Functions
 *
 * Purpose: Single import point for all utility functions
 * Features:
 * - Centralized exports
 * - Clean import statements
 * - Easy maintenance
 */

// Core API Classes
export { ApiError } from './ApiError.js';
export { ApiResponse } from './ApiResponse.js';

// Async Handlers
export {
  asyncHandler,
  asyncMiddleware,
  asyncErrorHandler,
} from './asyncHandler.js';
export { default as asyncHandler } from './asyncHandler.js';

// Validation Utilities
export { default as validationUtils } from './validationUtils.js';
export * from './validationUtils.js';

// Shared Utilities
export { default as sharedUtils } from './sharedUtils.js';
export * from './sharedUtils.js';

// Circuit Breakers
export { default as circuitBreakers } from './circuitBreakers.js';
export * from './circuitBreakers.js';

// Default export for backward compatibility
export default {
  ApiError,
  ApiResponse,
  asyncHandler,
  asyncMiddleware,
  asyncErrorHandler,
  validationUtils,
  sharedUtils,
  circuitBreakers,
};
