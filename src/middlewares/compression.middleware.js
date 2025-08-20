import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import zlib from 'zlib';
import { promisify } from 'util';

/**
 * Smart Compression Middleware
 * HTTP response compression with essential features
 */

// Promisify zlib functions
const gzip = promisify(zlib.gzip);
const deflate = promisify(zlib.deflate);

/**
 * Compression configuration
 */
const COMPRESSION_CONFIG = {
  // Minimum size to compress (1KB)
  minSize: 1024,

  // Maximum size to compress (10MB)
  maxSize: 10 * 1024 * 1024,

  // Compression level (0-9, higher = better compression but slower)
  compressionLevel: 6,

  // Supported compression algorithms
  algorithms: ['gzip', 'deflate'],

  // Content types to compress
  compressibleTypes: [
    'text/plain',
    'text/html',
    'text/css',
    'text/javascript',
    'application/javascript',
    'application/json',
    'application/xml',
    'application/xml+rss',
    'application/atom+xml',
    'application/x-yaml',
    'application/x-www-form-urlencoded',
  ],
};

/**
 * Check if content type is compressible
 */
function isCompressible(contentType) {
  if (!contentType) return false;

  return COMPRESSION_CONFIG.compressibleTypes.some(type =>
    contentType.includes(type)
  );
}

/**
 * Check if content should be compressed
 */
function shouldCompress(content, contentType, acceptEncoding) {
  // Check size
  if (!content || content.length < COMPRESSION_CONFIG.minSize) {
    return false;
  }

  if (content.length > COMPRESSION_CONFIG.maxSize) {
    return false;
  }

  // Check content type
  if (!isCompressible(contentType)) {
    return false;
  }

  // Check if client accepts compression
  if (!acceptEncoding) {
    return false;
  }

  return true;
}

/**
 * Get preferred compression algorithm
 */
function getPreferredAlgorithm(acceptEncoding) {
  if (acceptEncoding.includes('gzip')) {
    return 'gzip';
  }

  if (acceptEncoding.includes('deflate')) {
    return 'deflate';
  }

  return null;
}

/**
 * Compress content using specified algorithm
 */
async function compressContent(content, algorithm) {
  try {
    const options = {
      level: COMPRESSION_CONFIG.compressionLevel,
    };

    let compressed;
    switch (algorithm) {
      case 'gzip':
        compressed = await gzip(content, options);
        break;
      case 'deflate':
        compressed = await deflate(content, options);
        break;
      default:
        throw new Error(`Unsupported compression algorithm: ${algorithm}`);
    }

    return compressed;
  } catch (error) {
    safeLogger.error('Compression failed', {
      error: error.message,
      algorithm,
    });
    return null;
  }
}

/**
 * Main compression middleware
 */
export const compressionMiddleware = (options = {}) => {
  const config = { ...COMPRESSION_CONFIG, ...options };

  return async (req, res, next) => {
    const correlationId = getCorrelationId();

    try {
      // Store original send methods
      const originalSend = res.send;
      const originalJson = res.json;
      const originalEnd = res.end;

      // Override send method
      res.send = async function (body) {
        try {
          const contentType = res.get('Content-Type');
          const acceptEncoding = req.headers['accept-encoding'];

          if (shouldCompress(body, contentType, acceptEncoding)) {
            const algorithm = getPreferredAlgorithm(acceptEncoding);

            if (algorithm) {
              const compressed = await compressContent(body, algorithm);

              if (compressed) {
                // Set compression headers
                res.set('Content-Encoding', algorithm);
                res.set('Content-Length', compressed.length);
                res.set('Vary', 'Accept-Encoding');

                // Log compression
                const compressionRatio = (
                  ((body.length - compressed.length) / body.length) *
                  100
                ).toFixed(2);
                safeLogger.debug('Response compressed', {
                  correlationId,
                  path: req.path,
                  algorithm,
                  originalSize: body.length,
                  compressedSize: compressed.length,
                  compressionRatio: `${compressionRatio}%`,
                });

                return originalSend.call(this, compressed);
              }
            }
          }

          // Fallback to original send
          return originalSend.call(this, body);
        } catch (error) {
          safeLogger.error('Compression send error', {
            error: error.message,
            correlationId,
          });
          return originalSend.call(this, body);
        }
      };

      // Override json method
      res.json = async function (body) {
        try {
          const jsonString = JSON.stringify(body);
          const contentType = 'application/json';
          const acceptEncoding = req.headers['accept-encoding'];

          if (shouldCompress(jsonString, contentType, acceptEncoding)) {
            const algorithm = getPreferredAlgorithm(acceptEncoding);

            if (algorithm) {
              const compressed = await compressContent(jsonString, algorithm);

              if (compressed) {
                // Set compression headers
                res.set('Content-Encoding', algorithm);
                res.set('Content-Length', compressed.length);
                res.set('Vary', 'Accept-Encoding');

                // Log compression
                const compressionRatio = (
                  ((jsonString.length - compressed.length) /
                    jsonString.length) *
                  100
                ).toFixed(2);
                safeLogger.debug('JSON response compressed', {
                  correlationId,
                  path: req.path,
                  algorithm,
                  originalSize: jsonString.length,
                  compressedSize: compressed.length,
                  compressionRatio: `${compressionRatio}%`,
                });

                return originalSend.call(this, compressed);
              }
            }
          }

          // Fallback to original json
          return originalJson.call(this, body);
        } catch (error) {
          safeLogger.error('Compression json error', {
            error: error.message,
            correlationId,
          });
          return originalJson.call(this, body);
        }
      };

      // Override end method
      res.end = async function (chunk, encoding) {
        try {
          if (chunk && typeof chunk === 'string') {
            const contentType = res.get('Content-Type');
            const acceptEncoding = req.headers['accept-encoding'];

            if (shouldCompress(chunk, contentType, acceptEncoding)) {
              const algorithm = getPreferredAlgorithm(acceptEncoding);

              if (algorithm) {
                const compressed = await compressContent(chunk, algorithm);

                if (compressed) {
                  // Set compression headers
                  res.set('Content-Encoding', algorithm);
                  res.set('Content-Length', compressed.length);
                  res.set('Vary', 'Accept-Encoding');

                  // Log compression
                  const compressionRatio = (
                    ((chunk.length - compressed.length) / chunk.length) *
                    100
                  ).toFixed(2);
                  safeLogger.debug('Response end compressed', {
                    correlationId,
                    path: req.path,
                    algorithm,
                    originalSize: chunk.length,
                    compressedSize: compressed.length,
                    compressionRatio: `${compressionRatio}%`,
                  });

                  return originalEnd.call(this, compressed, encoding);
                }
              }
            }
          }

          // Fallback to original end
          return originalEnd.call(this, chunk, encoding);
        } catch (error) {
          safeLogger.error('Compression end error', {
            error: error.message,
            correlationId,
          });
          return originalEnd.call(this, chunk, encoding);
        }
      };

      next();
    } catch (error) {
      safeLogger.error('Compression middleware error', {
        error: error.message,
        correlationId,
      });
      next();
    }
  };
};

/**
 * Gzip-only compression middleware
 */
export const gzipMiddleware = (options = {}) => {
  return compressionMiddleware({
    ...options,
    algorithms: ['gzip'],
  });
};

/**
 * Deflate-only compression middleware
 */
export const deflateMiddleware = (options = {}) => {
  return compressionMiddleware({
    ...options,
    algorithms: ['deflate'],
  });
};

/**
 * Get compression statistics
 */
export const getCompressionStats = () => {
  return {
    config: COMPRESSION_CONFIG,
    algorithms: COMPRESSION_CONFIG.algorithms,
    compressibleTypes: COMPRESSION_CONFIG.compressibleTypes,
  };
};

export default {
  compressionMiddleware,
  gzipMiddleware,
  deflateMiddleware,
  getCompressionStats,
};
