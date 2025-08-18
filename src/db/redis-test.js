import Redis from 'ioredis';
import { redisConfig } from '../config/redis.js';
const redis = new Redis({
  host: redisConfig.host,
  port: redisConfig.port,
  db: redisConfig.db,
  //   family: 6,
});
redis.on('error', err => {
  // This is a test file, console.error is acceptable for debugging
  console.error('Main Redis client error event:', err);
});
redis.on('connect', () => {
  // This is a test file, console.log is acceptable for debugging
  console.log('Main Redis client connected event');
});
redis.on('ready', () => {
  // This is a test file, console.log is acceptable for debugging
  console.log('Main Redis client ready event');
});
