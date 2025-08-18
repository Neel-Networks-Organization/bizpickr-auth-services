#!/usr/bin/env node

/**
 * Simple Development Setup Script
 * For 2 developers - keeps it simple and focused
 */

import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync, copyFileSync, writeFileSync, readFileSync } from 'fs';

// Load environment variables
config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const projectRoot = join(__dirname, '..');
const envExamplePath = join(projectRoot, 'env.example');
const envPath = join(projectRoot, '.env');

console.log('🚀 AuthService Development Setup');
console.log('=================================');

// Check if .env already exists
if (existsSync(envPath)) {
  console.log('\n⚠️  .env file already exists!');
  console.log('If you want to recreate it, delete the existing .env file first.');
  process.exit(0);
}

// Check if env.example exists
if (!existsSync(envExamplePath)) {
  console.log('\n❌ env.example file not found!');
  console.log('Please make sure you\'re running this script from the authService directory.');
  process.exit(1);
}

try {
  // Copy env.example to .env
  copyFileSync(envExamplePath, envPath);
  console.log('✅ Created .env file from env.example');

  // Read the .env file
  let envContent = readFileSync(envPath, 'utf8');

  // Update critical development values
  const updates = {
    'NODE_ENV=production': 'NODE_ENV=development',
    'DB_PASSWORD=password': 'DB_PASSWORD=password',
    'REDIS_PASSWORD=': 'REDIS_PASSWORD=',
    'JWT_SECRET=your-super-secret-jwt-key-change-this-in-production': 'JWT_SECRET=dev-jwt-secret-change-in-production',
    'COOKIE_SECRET=your-super-secret-cookie-key-change-this-in-production': 'COOKIE_SECRET=dev-cookie-secret-change-in-production',
    'LOG_LEVEL=info': 'LOG_LEVEL=debug',
    'LOG_COLORIZE=false': 'LOG_COLORIZE=true',
    'LOG_TO_FILE=true': 'LOG_TO_FILE=false',
    'LOG_TO_CONSOLE=false': 'LOG_TO_CONSOLE=true'
  };

  // Apply updates
  for (const [oldValue, newValue] of Object.entries(updates)) {
    if (envContent.includes(oldValue)) {
      envContent = envContent.replace(oldValue, newValue);
      console.log(`✅ Updated: ${oldValue.split('=')[0]}`);
    }
  }

  // Write updated content back
  writeFileSync(envPath, envContent);

  console.log('\n🎉 Development environment configured successfully!');
  console.log('\n📋 Next Steps:');
  console.log('1. Review the .env file and update any specific values');
  console.log('2. Make sure your databases are running:');
  console.log('   - MySQL on localhost:3306');
  console.log('   - Redis on localhost:6379');
  console.log('   - RabbitMQ on localhost:5672');
  console.log('   - MongoDB on localhost:27017');
  console.log('3. Start development: npm run dev');

  console.log('\n⚠️  Important Security Notes:');
  console.log('- The generated JWT and cookie secrets are for development only');
  console.log('- Change these secrets before deploying to production');
  console.log('- Never commit the .env file to version control');

} catch (error) {
  console.error('❌ Failed to setup development environment:', error.message);
  process.exit(1);
}
