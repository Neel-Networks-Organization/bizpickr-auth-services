import { ApiError } from './ApiError.js';
import { safeLogger } from '../config/logger.js';

const asyncHandler = requestHandler => {
  return async (req, res, next) => {
    const requestId = req.correlationId;

    try {
      const result = await requestHandler(req, res, next);
      return result;
    } catch (error) {
      safeLogger.error('Request failed', {
        requestId,
        method: req.method,
        url: req.originalUrl || req.url,
        error: {
          message: error.message,
          name: error.name,
          stack:
            process.env.NODE_ENV === 'development' ? error.stack : undefined,
        },
      });

      if (error instanceof ApiError) {
        next(error);
      } else if (error.name && error.name.startsWith('Sequelize')) {
        next(error);
      } else {
        const apiError = new ApiError(
          500,
          'Internal Server Error',
          [error.message],
          process.env.NODE_ENV === 'development' ? error.stack : ''
        );
        next(apiError);
      }
    }
  };
};

export { asyncHandler };
export default asyncHandler;
