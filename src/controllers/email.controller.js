import { ApiError, ApiResponse } from '../utils/index.js';
import { emailService } from '../services/index.js';
import { safeLogger } from '../config/logger.js';

export const sendVerificationEmail = async (req, res) => {
  const { email } = req.body;

  const result = await emailService.sendVerificationEmail(email);

  safeLogger.info('Verification email sent', { email });

  return res.status(200).json(
    ApiResponse.success({}, 'Verification email sent', {
      email,
      expiresAt: result.expiresAt,
      expiresIn: result.expiresIn,
    })
  );
};

export const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;

  const result = await emailService.verifyEmail(email, otp);

  if (!result) {
    throw new ApiError(400, 'Email verification failed');
  }

  safeLogger.info('Email verified', { email });

  return res.status(200).json(
    ApiResponse.success({}, 'Email verified', {
      email,
      isVerified: result,
    })
  );
};

export const getVerificationStats = async (req, res) => {
  const result = await emailService.getVerificationStats();

  return res.status(200).json(
    ApiResponse.success({}, 'Verification stats', {
      stats: result,
    })
  );
};

export const getVerificationStatsByEmail = async (req, res) => {
  const { email } = req.body;

  const result = await emailService.getVerificationStatsByEmail(email);

  return res.status(200).json(
    ApiResponse.success({}, 'Verification stats by email', {
      email,
      stats: result,
    })
  );
};
