import mongoose from 'mongoose';
import { MONGODB_URI } from '../config/env.js';
import { safeLogger } from '../config/logger.js';

const uri =
  MONGODB_URI ||
  process.env.MONGODB_URI ||
  'mongodb://localhost:27017/authService';

mongoose.connection.on('connected', () => {
  safeLogger.info('MongoDB connected');
});

mongoose.connection.on('error', err => {
  safeLogger.error('MongoDB connection error', { error: err.message });
});

mongoose.connection.on('disconnected', () => {
  safeLogger.warn('MongoDB disconnected');
});

export const connectMongo = async() => {
  try {
    await mongoose.connect(uri);
    safeLogger.info('MongoDB connection established');
  } catch (err) {
    safeLogger.error('MongoDB connection failed', { error: err.message });
    throw err;
  }
};

export default mongoose;
