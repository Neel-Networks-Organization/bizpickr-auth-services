import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/ApiError.js';
import zlib from 'zlib';
import { promisify } from 'util';
/**
 * Socket.IO Compression Middleware
 *
 * Features:
 * - Data compression and decompression
 * - Compression level optimization
 * - Size threshold management
 * - Performance monitoring
 * - Error handling and recovery
 * - Compression statistics
 */
class CompressionMiddleware {
  constructor() {
    this.compressionStats = {
      totalCompressed: 0,
      totalUncompressed: 0,
      compressionRatio: 0,
      compressionTime: 0,
      decompressionTime: 0,
      errors: 0,
    };
    this.config = {
      minSize: 1024, // Minimum size to compress (1KB)
      maxSize: 1024 * 1024, // Maximum size to compress (1MB)
      compressionLevel: 6, // zlib compression level (0-9)
      algorithm: 'gzip', // Compression algorithm
      enabled: true,
    };
    // Promisify zlib functions
    this.gzip = promisify(zlib.gzip);
    this.gunzip = promisify(zlib.gunzip);
    this.deflate = promisify(zlib.deflate);
    this.inflate = promisify(zlib.inflate);
  }
  /**
   * Main compression middleware function
   * @param {Object} socket - Socket.IO socket instance
   * @param {Function} next - Next middleware function
   */
  compress(socket, next) {
    const correlationId = getCorrelationId();
    const startTime = Date.now();
    try {
      // Add compression methods to socket
      this._addCompressionMethods(socket);
      // Wrap socket events for compression
      this._wrapSocketEvents(socket);
      const processingTime = Date.now() - startTime;
      safeLogger.debug('Compression middleware applied successfully', {
        socketId: socket.id,
        correlationId,
        processingTime,
        config: this.config,
      });
      next();
    } catch (error) {
      safeLogger.error('Compression middleware error', {
        error: error.message,
        socketId: socket.id,
        correlationId,
      });
      next(new Error('Compression setup failed'));
    }
  }
  /**
   * Add compression methods to socket
   * @private
   */
  _addCompressionMethods(socket) {
    // Add compression method
    socket.compress = async data => {
      return await this._compressData(data);
    };
    // Add decompression method
    socket.decompress = async compressedData => {
      return await this._decompressData(compressedData);
    };
    // Add compression helper
    socket.compressIfNeeded = async data => {
      return await this._compressIfNeeded(data);
    };
    // Add decompression helper
    socket.decompressIfNeeded = async data => {
      return await this._decompressIfNeeded(data);
    };
  }
  /**
   * Wrap socket events for compression
   * @private
   */
  _wrapSocketEvents(socket) {
    const originalEmit = socket.emit;
    const originalOn = socket.on;
    // Wrap emit to compress outgoing data
    socket.emit = async (event, data, ...args) => {
      try {
        const compressedData = await this._compressIfNeeded(data);
        return originalEmit.call(socket, event, compressedData, ...args);
      } catch (error) {
        safeLogger.error('Error compressing outgoing data', {
          error: error.message,
          socketId: socket.id,
          event,
        });
        // Fallback to original data
        return originalEmit.call(socket, event, data, ...args);
      }
    };
    // Wrap on to decompress incoming data
    socket.on = (event, handler) => {
      const wrappedHandler = async (...args) => {
        try {
          if (args.length > 0) {
            // Decompress first argument (data)
            const decompressedData = await this._decompressIfNeeded(args[0]);
            args[0] = decompressedData;
          }
          // Call original handler
          return await handler.apply(socket, args);
        } catch (error) {
          await this._handleCompressionError(socket, event, error);
        }
      };
      return originalOn.call(socket, event, wrappedHandler);
    };
  }
  /**
   * Compress data if needed
   * @private
   */
  async _compressIfNeeded(data) {
    if (!this.config.enabled || !data) {
      return data;
    }
    const dataString = JSON.stringify(data);
    const dataSize = Buffer.byteLength(dataString, 'utf8');
    // Check if compression is beneficial
    if (dataSize < this.config.minSize || dataSize > this.config.maxSize) {
      return data;
    }
    try {
      const compressedData = await this._compressData(dataString);
      const compressedSize = Buffer.byteLength(compressedData, 'base64');
      // Only use compression if it actually reduces size
      if (compressedSize < dataSize) {
        return {
          __compressed: true,
          algorithm: this.config.algorithm,
          data: compressedData,
          originalSize: dataSize,
          compressedSize: compressedSize,
        };
      }
      return data;
    } catch (error) {
      safeLogger.warn('Compression failed, returning original data', {
        error: error.message,
        dataSize,
      });
      return data;
    }
  }
  /**
   * Decompress data if needed
   * @private
   */
  async _decompressIfNeeded(data) {
    if (!data || typeof data !== 'object' || !data.__compressed) {
      return data;
    }
    try {
      const decompressedData = await this._decompressData(
        data.data,
        data.algorithm
      );
      return JSON.parse(decompressedData);
    } catch (error) {
      safeLogger.error('Decompression failed', {
        error: error.message,
        algorithm: data.algorithm,
      });
      throw new ApiError(400, 'Failed to decompress data');
    }
  }
  /**
   * Compress data using specified algorithm
   * @private
   */
  async _compressData(data) {
    const startTime = Date.now();
    const correlationId = getCorrelationId();
    try {
      let compressedData;
      switch (this.config.algorithm) {
        case 'gzip':
          compressedData = await this.gzip(data, {
            level: this.config.compressionLevel,
          });
          break;
        case 'deflate':
          compressedData = await this.deflate(data, {
            level: this.config.compressionLevel,
          });
          break;
        default:
          throw new Error(
            `Unsupported compression algorithm: ${this.config.algorithm}`
          );
      }
      const processingTime = Date.now() - startTime;
      const originalSize = Buffer.byteLength(data, 'utf8');
      const compressedSize = compressedData.length;
      // Update statistics
      this._updateStats(originalSize, compressedSize, processingTime, 0);
      safeLogger.debug('Data compressed successfully', {
        correlationId,
        algorithm: this.config.algorithm,
        originalSize,
        compressedSize,
        compressionRatio:
          ((1 - compressedSize / originalSize) * 100).toFixed(2) + '%',
        processingTime,
      });
      return compressedData.toString('base64');
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.compressionStats.errors++;
      safeLogger.error('Compression failed', {
        error: error.message,
        correlationId,
        processingTime,
      });
      throw error;
    }
  }
  /**
   * Decompress data using specified algorithm
   * @private
   */
  async _decompressData(compressedData, algorithm = 'gzip') {
    const startTime = Date.now();
    const correlationId = getCorrelationId();
    try {
      const buffer = Buffer.from(compressedData, 'base64');
      let decompressedData;
      switch (algorithm) {
        case 'gzip':
          decompressedData = await this.gunzip(buffer);
          break;
        case 'deflate':
          decompressedData = await this.inflate(buffer);
          break;
        default:
          throw new Error(`Unsupported decompression algorithm: ${algorithm}`);
      }
      const processingTime = Date.now() - startTime;
      const compressedSize = buffer.length;
      const decompressedSize = decompressedData.length;
      // Update statistics
      this._updateStats(decompressedSize, compressedSize, 0, processingTime);
      safeLogger.debug('Data decompressed successfully', {
        correlationId,
        algorithm,
        compressedSize,
        decompressedSize,
        processingTime,
      });
      return decompressedData.toString('utf8');
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.compressionStats.errors++;
      safeLogger.error('Decompression failed', {
        error: error.message,
        correlationId,
        algorithm,
        processingTime,
      });
      throw error;
    }
  }
  /**
   * Update compression statistics
   * @private
   */
  _updateStats(
    originalSize,
    compressedSize,
    compressionTime,
    decompressionTime
  ) {
    this.compressionStats.totalUncompressed += originalSize;
    this.compressionStats.totalCompressed += compressedSize;
    this.compressionStats.compressionTime += compressionTime;
    this.compressionStats.decompressionTime += decompressionTime;
    if (this.compressionStats.totalUncompressed > 0) {
      this.compressionStats.compressionRatio =
        (1 -
          this.compressionStats.totalCompressed /
            this.compressionStats.totalUncompressed) *
        100;
    }
  }
  /**
   * Handle compression errors
   * @private
   */
  async _handleCompressionError(socket, event, error) {
    const correlationId = getCorrelationId();
    try {
      // Emit error to client
      socket.emit('compression_error', {
        event,
        error: error.message,
        timestamp: Date.now(),
        code: error.statusCode || 500,
      });
      // Log error
      safeLogger.warn('Compression error sent to client', {
        socketId: socket.id,
        event,
        error: error.message,
        correlationId,
      });
    } catch (emitError) {
      safeLogger.error('Failed to emit compression error', {
        error: emitError.message,
        originalError: error.message,
        socketId: socket.id,
        event,
        correlationId,
      });
    }
  }
  /**
   * Configure compression settings
   * @param {Object} config - Configuration object
   */
  configure(config) {
    this.config = { ...this.config, ...config };
    safeLogger.info('Compression middleware configured', {
      config: this.config,
    });
  }
  /**
   * Enable/disable compression
   * @param {boolean} enabled - Whether to enable compression
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
    safeLogger.info(`Compression ${enabled ? 'enabled' : 'disabled'}`);
  }
  /**
   * Set compression algorithm
   * @param {string} algorithm - Compression algorithm ('gzip' or 'deflate')
   */
  setAlgorithm(algorithm) {
    if (!['gzip', 'deflate'].includes(algorithm)) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    this.config.algorithm = algorithm;
    safeLogger.info(`Compression algorithm set to: ${algorithm}`);
  }
  /**
   * Set compression level
   * @param {number} level - Compression level (0-9)
   */
  setCompressionLevel(level) {
    if (level < 0 || level > 9) {
      throw new Error('Compression level must be between 0 and 9');
    }
    this.config.compressionLevel = level;
    safeLogger.info(`Compression level set to: ${level}`);
  }
  /**
   * Set size thresholds
   * @param {number} minSize - Minimum size to compress
   * @param {number} maxSize - Maximum size to compress
   */
  setSizeThresholds(minSize, maxSize) {
    if (minSize < 0 || maxSize < minSize) {
      throw new Error('Invalid size thresholds');
    }
    this.config.minSize = minSize;
    this.config.maxSize = maxSize;
    safeLogger.info(`Size thresholds set: min=${minSize}, max=${maxSize}`);
  }
  /**
   * Get compression statistics
   * @returns {Object} Compression statistics
   */
  getStats() {
    return {
      ...this.compressionStats,
      config: this.config,
      averageCompressionTime:
        this.compressionStats.compressionTime /
        (this.compressionStats.totalUncompressed > 0 ? 1 : 0),
      averageDecompressionTime:
        this.compressionStats.decompressionTime /
        (this.compressionStats.totalCompressed > 0 ? 1 : 0),
    };
  }
  /**
   * Reset statistics
   */
  resetStats() {
    this.compressionStats = {
      totalCompressed: 0,
      totalUncompressed: 0,
      compressionRatio: 0,
      compressionTime: 0,
      decompressionTime: 0,
      errors: 0,
    };
    safeLogger.info('Compression statistics reset');
  }
  /**
   * Clean up resources
   */
  cleanup() {
    this.resetStats();
  }
}
// Create singleton instance
const compressionMiddleware = new CompressionMiddleware();
// Export middleware function
export default (socket, next) => compressionMiddleware.compress(socket, next);
// Export class for direct usage
export { CompressionMiddleware };
