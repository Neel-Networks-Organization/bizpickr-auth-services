#!/usr/bin/env node

/**
 * Simple Development Server
 * Starts the server with all external dependencies skipped
 */

import { spawn } from 'child_process';

console.log('🚀 Starting simple development server...');

// Set environment variables
const env = {
  ...process.env,
  NODE_ENV: 'development',
  PORT: '3001',
  JWT_SECRET: 'dev-secret-key-change-in-production',
  REFRESH_TOKEN_SECRET: 'dev-refresh-secret-key-change-in-production',
  SKIP_DB: 'true',
  SKIP_REDIS: 'true',
  SKIP_RABBITMQ: 'true',
  SKIP_MONGODB: 'true',
};

// Start the server
const server = spawn('node', ['src/index.js'], {
  stdio: 'inherit',
  env,
  cwd: process.cwd(),
});

server.on('error', error => {
  console.error('❌ Server error:', error.message);
  process.exit(1);
});

server.on('exit', code => {
  console.log(`Server exited with code ${code}`);
  process.exit(code);
});

// Handle process signals
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  server.kill('SIGINT');
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down server...');
  server.kill('SIGTERM');
});
