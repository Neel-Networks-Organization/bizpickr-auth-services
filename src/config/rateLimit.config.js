/**
 * Centralized Rate Limiting Configuration
 * Single source of truth for all rate limits across the application
 */

export const rateLimitConfig = {
  // Global app level rate limiting (enterpriseRateLimit)
  global: {
    maxRequests: parseInt(process.env.GLOBAL_RATE_LIMIT) || 100,
    windowMs: parseInt(process.env.GLOBAL_RATE_WINDOW) || 15 * 60 * 1000, // 15 minutes
  },

  // Route specific rate limits (ipRateLimit)
  routes: {
    auth: {
      signup: {
        windowMs: parseInt(process.env.AUTH_SIGNUP_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.AUTH_SIGNUP_LIMIT) || 5,
      },
      login: {
        windowMs: parseInt(process.env.AUTH_LOGIN_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.AUTH_LOGIN_LIMIT) || 10,
      },
      refreshToken: {
        windowMs: parseInt(process.env.AUTH_REFRESH_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.AUTH_REFRESH_LIMIT) || 20,
      },
      logout: {
        windowMs: parseInt(process.env.AUTH_LOGOUT_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.AUTH_LOGOUT_LIMIT) || 50,
      },
      twoFactor: {
        enable: {
          windowMs:
            parseInt(process.env.AUTH_2FA_ENABLE_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_2FA_ENABLE_LIMIT) || 5,
        },
        disable: {
          windowMs:
            parseInt(process.env.AUTH_2FA_DISABLE_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_2FA_DISABLE_LIMIT) || 5,
        },
        verify: {
          windowMs:
            parseInt(process.env.AUTH_2FA_VERIFY_WINDOW) || 5 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_2FA_VERIFY_LIMIT) || 10,
        },
      },
      oauth: {
        google: {
          windowMs: parseInt(process.env.AUTH_GOOGLE_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_GOOGLE_LIMIT) || 10,
        },
        googleCallback: {
          windowMs:
            parseInt(process.env.AUTH_GOOGLE_CALLBACK_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_GOOGLE_CALLBACK_LIMIT) || 10,
        },
      },
      admin: {
        unlock: {
          windowMs:
            parseInt(process.env.AUTH_ADMIN_UNLOCK_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_ADMIN_UNLOCK_LIMIT) || 20,
        },
        status: {
          windowMs:
            parseInt(process.env.AUTH_ADMIN_STATUS_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_ADMIN_STATUS_LIMIT) || 30,
        },
        suspend: {
          windowMs:
            parseInt(process.env.AUTH_ADMIN_SUSPEND_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_ADMIN_SUSPEND_LIMIT) || 20,
        },
        activate: {
          windowMs:
            parseInt(process.env.AUTH_ADMIN_ACTIVATE_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_ADMIN_ACTIVATE_LIMIT) || 20,
        },
        lockedAccounts: {
          windowMs:
            parseInt(process.env.AUTH_ADMIN_LOCKED_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_ADMIN_LOCKED_LIMIT) || 30,
        },
        clearCache: {
          windowMs:
            parseInt(process.env.AUTH_ADMIN_CACHE_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_ADMIN_CACHE_LIMIT) || 20,
        },
      },
      dev: {
        activateAccount: {
          windowMs:
            parseInt(process.env.AUTH_DEV_ACTIVATE_WINDOW) || 15 * 60 * 1000,
          maxRequests: parseInt(process.env.AUTH_DEV_ACTIVATE_LIMIT) || 10,
        },
      },
    },

    password: {
      change: {
        windowMs: parseInt(process.env.PASSWORD_CHANGE_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.PASSWORD_CHANGE_LIMIT) || 10,
      },
      forgot: {
        windowMs:
          parseInt(process.env.PASSWORD_FORGOT_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.PASSWORD_FORGOT_LIMIT) || 3,
      },
      reset: {
        windowMs: parseInt(process.env.PASSWORD_RESET_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.PASSWORD_RESET_LIMIT) || 3,
      },
      stats: {
        windowMs: parseInt(process.env.PASSWORD_STATS_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.PASSWORD_STATS_LIMIT) || 20,
      },
      cleanup: {
        windowMs: parseInt(process.env.PASSWORD_CLEANUP_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.PASSWORD_CLEANUP_LIMIT) || 10,
      },
    },

    jwk: {
      jwks: {
        windowMs: parseInt(process.env.JWK_JWKS_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.JWK_JWKS_LIMIT) || 100,
      },
      key: {
        windowMs: parseInt(process.env.JWK_KEY_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.JWK_KEY_LIMIT) || 50,
      },
      refresh: {
        windowMs: parseInt(process.env.JWK_REFRESH_WINDOW) || 60 * 60 * 1000,
        maxRequests: parseInt(process.env.JWK_REFRESH_LIMIT) || 10,
      },
      validate: {
        windowMs: parseInt(process.env.JWK_VALIDATE_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.JWK_VALIDATE_LIMIT) || 30,
      },
      stats: {
        windowMs: parseInt(process.env.JWK_STATS_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.JWK_STATS_LIMIT) || 20,
      },
      health: {
        windowMs: parseInt(process.env.JWK_HEALTH_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.JWK_HEALTH_LIMIT) || 20,
      },
    },

    email: {
      sendVerification: {
        windowMs: parseInt(process.env.EMAIL_SEND_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.EMAIL_SEND_LIMIT) || 3,
      },
      verify: {
        windowMs: parseInt(process.env.EMAIL_VERIFY_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.EMAIL_VERIFY_LIMIT) || 3,
      },
      stats: {
        windowMs: parseInt(process.env.EMAIL_STATS_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.EMAIL_STATS_LIMIT) || 20,
      },
    },

    session: {
      validate: {
        windowMs: parseInt(process.env.SESSION_VALIDATE_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.SESSION_VALIDATE_LIMIT) || 30,
      },
      cleanup: {
        windowMs: parseInt(process.env.SESSION_CLEANUP_WINDOW) || 60 * 1000,
        maxRequests: parseInt(process.env.SESSION_CLEANUP_LIMIT) || 10,
      },
    },

    docs: {
      swagger: {
        windowMs: parseInt(process.env.DOCS_SWAGGER_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.DOCS_SWAGGER_LIMIT) || 100,
      },
      spec: {
        windowMs: parseInt(process.env.DOCS_SPEC_WINDOW) || 15 * 60 * 1000,
        maxRequests: parseInt(process.env.DOCS_SPEC_LIMIT) || 50,
      },
    },
  },
};

// Helper function to get rate limit config for a specific route
export const getRateLimitConfig = (category, route) => {
  if (
    rateLimitConfig.routes[category] &&
    rateLimitConfig.routes[category][route]
  ) {
    return rateLimitConfig.routes[category][route];
  }

  // Return default config if specific route not found
  return {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
  };
};

// Helper function to get global config
export const getGlobalRateLimitConfig = () => {
  return rateLimitConfig.global;
};
