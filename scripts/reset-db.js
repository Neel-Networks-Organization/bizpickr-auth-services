#!/usr/bin/env node

/**
 * Database Reset Script
 * Drops and recreates all tables for development
 */

import { sequelize } from '../src/db/index.js';
import { safeLogger } from '../src/config/logger.js';

console.log('🗄️ Resetting database...');

try {
  // Force drop all tables
  await sequelize.drop({ force: true });
  console.log('✅ All tables dropped');

  // Sync all models (recreate tables)
  await sequelize.sync({ force: true });
  console.log('✅ All tables recreated');

  console.log('🎉 Database reset completed successfully!');
} catch (error) {
  console.error('❌ Database reset failed:', error.message);
  safeLogger.error('Database reset failed', {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
} finally {
  await sequelize.close();
}
