import { cacheWarmingService } from './cacheWarming.service.js';
import { safeLogger } from '../config/logger.js';

export const initializeServices = async () => {
  try {
    // Initialize cache warming
    await cacheWarmingService.scheduleWarming();
    safeLogger.info('Cache warming service initialized');
  } catch (error) {
    safeLogger.error('Failed to initialize services', { error: error.message });
  }
};
