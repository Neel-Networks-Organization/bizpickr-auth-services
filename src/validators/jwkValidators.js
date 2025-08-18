import Joi from 'joi';

/**
 * Smart JWK Validators - Essential Only
 * Basic JSON Web Key validation without over-engineering
 */

// ✅ Essential key types
const KEY_TYPES = {
  RSA: 'RSA',
  EC: 'EC',
  OCT: 'oct',
};

// ✅ Essential algorithms
const KEY_ALGORITHMS = {
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512',
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
};

// ✅ Essential operations
const KEY_OPERATIONS = {
  SIGN: 'sign',
  VERIFY: 'verify',
  ENCRYPT: 'encrypt',
  DECRYPT: 'decrypt',
};

// ✅ Essential key usage
const KEY_USAGE = {
  DIGITAL_SIGNATURE: 'digitalSignature',
  KEY_ENCIPHERMENT: 'keyEncipherment',
  DATA_ENCIPHERMENT: 'dataEncipherment',
};

/**
 * Basic JWK validation schemas
 */
export const jwkValidators = {
  // Create JWK
  createJwk: Joi.object({
    kty: Joi.string().valid(...Object.values(KEY_TYPES)).required(),
    alg: Joi.string().valid(...Object.values(KEY_ALGORITHMS)).required(),
    use: Joi.string().valid(...Object.values(KEY_USAGE)).optional(),
    key_ops: Joi.array().items(Joi.string().valid(...Object.values(KEY_OPERATIONS))).optional(),
    kid: Joi.string().max(255).optional(),
    x5u: Joi.string().uri().optional(),
    x5c: Joi.array().items(Joi.string()).optional(),
    x5t: Joi.string().optional(),
    'x5t#S256': Joi.string().optional(),
  }),

  // Update JWK
  updateJwk: Joi.object({
    kty: Joi.string().valid(...Object.values(KEY_TYPES)).optional(),
    alg: Joi.string().valid(...Object.values(KEY_ALGORITHMS)).optional(),
    use: Joi.string().valid(...Object.values(KEY_USAGE)).optional(),
    key_ops: Joi.array().items(Joi.string().valid(...Object.values(KEY_OPERATIONS))).optional(),
    kid: Joi.string().max(255).optional(),
    x5u: Joi.string().uri().optional(),
    x5c: Joi.array().items(Joi.string()).optional(),
    x5t: Joi.string().optional(),
    'x5t#S256': Joi.string().optional(),
  }),

  // JWK ID validation
  jwkId: Joi.object({
    kid: Joi.string().required(),
  }),

  // JWK list query
  listJwks: Joi.object({
    limit: Joi.number().integer().min(1).max(100).default(20),
    offset: Joi.number().integer().min(0).default(0),
    kty: Joi.string().valid(...Object.values(KEY_TYPES)).optional(),
    alg: Joi.string().valid(...Object.values(KEY_ALGORITHMS)).optional(),
    use: Joi.string().valid(...Object.values(KEY_USAGE)).optional(),
  }),
};

// ✅ Export default
export default jwkValidators;

// ✅ Export constants
export {
  KEY_TYPES,
  KEY_ALGORITHMS,
  KEY_OPERATIONS,
  KEY_USAGE,
};

// ✅ Export validation functions for backward compatibility
export const validateJWKRequest = (data) => {
  const { error, value } = jwkValidators.createJwk.validate(data);
  if (error) {
    throw new Error(`JWK validation error: ${error.details[0].message}`);
  }
  return value;
};
