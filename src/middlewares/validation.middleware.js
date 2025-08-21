import Joi from 'joi';
import { ApiError } from '../utils/index.js';

/**
 * Validation Middleware
 * Core request validation functionality
 */

/**
 * Validate request against Joi schema
 */
export const validateRequest = (schema, options = {}) => {
  return (req, res, next) => {
    const {
      abortEarly = false,
      allowUnknown = true,
      stripUnknown = true,
    } = options;

    try {
      // Validate request body
      if (schema.body) {
        const { error, value } = schema.body.validate(req.body, {
          abortEarly,
          allowUnknown,
          stripUnknown,
        });

        if (error) {
          const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');
          return next(new ApiError(400, `Validation Error: ${errorMessage}`));
        }

        req.body = value;
      }

      // Validate request query
      if (schema.query) {
        const { error, value } = schema.query.validate(req.query, {
          abortEarly,
          allowUnknown,
          stripUnknown,
        });

        if (error) {
          const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');
          return next(
            new ApiError(400, `Query Validation Error: ${errorMessage}`)
          );
        }

        req.query = value;
      }

      // Validate request parameters
      if (schema.params) {
        const { error, value } = schema.params.validate(req.params, {
          abortEarly,
          allowUnknown,
          stripUnknown,
        });

        if (error) {
          const errorMessage = error.details
            .map(detail => detail.message)
            .join(', ');
          return next(
            new ApiError(400, `Parameter Validation Error: ${errorMessage}`)
          );
        }

        req.params = value;
      }

      next();
    } catch (error) {
      next(new ApiError(500, 'Validation processing error'));
    }
  };
};

export default {
  validateRequest,
};
