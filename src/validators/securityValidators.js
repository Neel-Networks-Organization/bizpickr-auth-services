import { safeLogger } from '../config/logger.js';
/**
 * Security Validators
 *
 * Features:
 * - SQL Injection detection
 * - XSS attack detection
 * - CSRF token validation
 * - Rate limiting validation
 * - Input sanitization
 * - Security threat detection
 * - Malicious pattern detection
 * - Security metrics collection
 * - Real-time threat monitoring
 * - Security incident logging
 * - Compliance validation
 * - Enterprise-grade security rules
 */
// ✅ Security Configuration
const SECURITY_CONFIG = {
  // Threat detection
  enableSqlInjectionDetection: true,
  enableXssDetection: true,
  enableCsrfProtection: true,
  enableRateLimiting: true,
  enableInputSanitization: true,
  // Pattern detection
  sqlInjectionPatterns: [
    /(\b(union|select|insert|update|delete|drop|create|alter)\b)/i,
    /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
    /(\b(union|select)\b.*\bfrom\b)/i,
    /(\b(union|select)\b.*\bwhere\b)/i,
    /(\b(insert|update)\b.*\binto\b)/i,
    /(\b(delete)\b.*\bfrom\b)/i,
    /(\b(drop|create|alter)\b.*\b(table|database|index)\b)/i,
    /(\b(exec|execute)\b)/i,
    /(\b(xp_|sp_)\w+)/i,
    /(\b(declare|cast|convert)\b)/i,
  ],
  xssPatterns: [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
    /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi,
    /<link\b[^<]*>/gi,
    /<meta\b[^<]*>/gi,
    /vbscript:/gi,
    /data:text\/html/gi,
    /data:application\/javascript/gi,
  ],
  // Malicious patterns
  maliciousPatterns: [
    /(\b(eval|setTimeout|setInterval|Function)\s*\()/gi,
    /(\b(document\.|window\.|location\.|history\.)\w+)/gi,
    /(\b(alert|confirm|prompt)\s*\()/gi,
    /(\b(innerHTML|outerHTML|insertAdjacentHTML)\s*=)/gi,
    /(\b(document\.write|document\.writeln)\s*\()/gi,
    /(\b(unescape|escape|encodeURI|decodeURI)\s*\()/gi,
    /(\b(atob|btoa)\s*\()/gi,
    /(\b(import|export)\s+)/gi,
    /(\b(require|module|exports)\s*)/gi,
  ],
  // File upload threats
  fileUploadThreats: [
    /\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|aspx|exe|bat|cmd|com|scr|pif|vbs|js)$/i,
    /\.(htaccess|htpasswd|ini|log|sh|sql|bak|tmp|temp)$/i,
  ],
  // Command injection patterns
  commandInjectionPatterns: [
    /(\b(cat|ls|dir|rm|del|cp|mv|chmod|chown|sudo|su)\b)/i,
    /(\b(ping|nslookup|dig|traceroute|netstat|ps|top|kill)\b)/i,
    /(\b(wget|curl|nc|telnet|ssh|ftp|scp|rsync)\b)/i,
    /(\b(echo|printf|grep|sed|awk|sort|uniq|head|tail)\b)/i,
    /(\b(ifconfig|ipconfig|route|arp|iptables|firewall)\b)/i,
  ],
  // Path traversal patterns
  pathTraversalPatterns: [
    /\.\.\//g,
    /\.\.\\/g,
    /%2e%2e%2f/gi,
    /%2e%2e%5c/gi,
    /\.\.%2f/gi,
    /\.\.%5c/gi,
  ],
  // Rate limiting
  maxRequestsPerMinute: 100,
  maxRequestsPerHour: 1000,
  maxLoginAttempts: 5,
  maxSignupAttempts: 3,
  // CSRF protection
  csrfTokenLength: 32,
  csrfTokenExpiry: 3600, // 1 hour
  // Input sanitization
  maxInputLength: 10000,
  allowedHtmlTags: [],
  stripScripts: true,
  stripStyles: true,
  // Logging
  logAllThreats: true,
  logSecurityIncidents: true,
  enableMetrics: true,
};
// ✅ Security Metrics
const securityMetrics = {
  totalRequests: 0,
  threatsDetected: 0,
  sqlInjectionAttempts: 0,
  xssAttempts: 0,
  csrfViolations: 0,
  rateLimitViolations: 0,
  fileUploadThreats: 0,
  commandInjectionAttempts: 0,
  pathTraversalAttempts: 0,
  maliciousPatterns: 0,
  blockedRequests: 0,
  securityIncidents: [],
};
// ✅ Rate Limiting Storage
const rateLimitStore = new Map();
/**
 * Detect SQL injection attempts
 */
export function detectSqlInjection(input) {
  if (!SECURITY_CONFIG.enableSqlInjectionDetection) return { detected: false };
  const threats = [];
  for (const pattern of SECURITY_CONFIG.sqlInjectionPatterns) {
    if (pattern.test(input)) {
      threats.push({
        type: 'sql_injection',
        pattern: pattern.source,
        severity: 'high',
        input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
      });
    }
  }
  if (threats.length > 0) {
    securityMetrics.sqlInjectionAttempts++;
    securityMetrics.threatsDetected++;
    if (SECURITY_CONFIG.logAllThreats) {
      safeLogger.warn('SQL injection attempt detected', {
        threats,
        input: input.substring(0, 200),
      });
    }
    return { detected: true, threats };
  }
  return { detected: false };
}
/**
 * Detect XSS attacks
 */
export function detectXss(input) {
  if (!SECURITY_CONFIG.enableXssDetection) return { detected: false };
  const threats = [];
  for (const pattern of SECURITY_CONFIG.xssPatterns) {
    if (pattern.test(input)) {
      threats.push({
        type: 'xss',
        pattern: pattern.source,
        severity: 'high',
        input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
      });
    }
  }
  if (threats.length > 0) {
    securityMetrics.xssAttempts++;
    securityMetrics.threatsDetected++;
    if (SECURITY_CONFIG.logAllThreats) {
      safeLogger.warn('XSS attempt detected', {
        threats,
        input: input.substring(0, 200),
      });
    }
    return { detected: true, threats };
  }
  return { detected: false };
}
/**
 * Detect malicious patterns
 */
export function detectMaliciousPatterns(input) {
  const threats = [];
  for (const pattern of SECURITY_CONFIG.maliciousPatterns) {
    if (pattern.test(input)) {
      threats.push({
        type: 'malicious_pattern',
        pattern: pattern.source,
        severity: 'medium',
        input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
      });
    }
  }
  if (threats.length > 0) {
    securityMetrics.maliciousPatterns++;
    securityMetrics.threatsDetected++;
    if (SECURITY_CONFIG.logAllThreats) {
      safeLogger.warn('Malicious pattern detected', {
        threats,
        input: input.substring(0, 200),
      });
    }
    return { detected: true, threats };
  }
  return { detected: false };
}
/**
 * Detect command injection attempts
 */
export function detectCommandInjection(input) {
  const threats = [];
  for (const pattern of SECURITY_CONFIG.commandInjectionPatterns) {
    if (pattern.test(input)) {
      threats.push({
        type: 'command_injection',
        pattern: pattern.source,
        severity: 'high',
        input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
      });
    }
  }
  if (threats.length > 0) {
    securityMetrics.commandInjectionAttempts++;
    securityMetrics.threatsDetected++;
    if (SECURITY_CONFIG.logAllThreats) {
      safeLogger.warn('Command injection attempt detected', {
        threats,
        input: input.substring(0, 200),
      });
    }
    return { detected: true, threats };
  }
  return { detected: false };
}
/**
 * Detect path traversal attempts
 */
export function detectPathTraversal(input) {
  const threats = [];
  for (const pattern of SECURITY_CONFIG.pathTraversalPatterns) {
    if (pattern.test(input)) {
      threats.push({
        type: 'path_traversal',
        pattern: pattern.source,
        severity: 'high',
        input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
      });
    }
  }
  if (threats.length > 0) {
    securityMetrics.pathTraversalAttempts++;
    securityMetrics.threatsDetected++;
    if (SECURITY_CONFIG.logAllThreats) {
      safeLogger.warn('Path traversal attempt detected', {
        threats,
        input: input.substring(0, 200),
      });
    }
    return { detected: true, threats };
  }
  return { detected: false };
}
/**
 * Validate file upload security
 */
export function validateFileUpload(file) {
  const threats = [];
  // Check file extension
  for (const pattern of SECURITY_CONFIG.fileUploadThreats) {
    if (pattern.test(file.originalname || file.name)) {
      threats.push({
        type: 'file_upload_threat',
        pattern: pattern.source,
        severity: 'high',
        filename: file.originalname || file.name,
      });
    }
  }
  // Check file size
  if (file.size > SECURITY_CONFIG.maxInputLength) {
    threats.push({
      type: 'file_size_exceeded',
      severity: 'medium',
      size: file.size,
      maxSize: SECURITY_CONFIG.maxInputLength,
    });
  }
  // Check MIME type
  if (
    file.mimetype &&
    !SECURITY_CONFIG.allowedHtmlTags.includes(file.mimetype)
  ) {
    threats.push({
      type: 'invalid_mime_type',
      severity: 'medium',
      mimeType: file.mimetype,
    });
  }
  if (threats.length > 0) {
    securityMetrics.fileUploadThreats++;
    securityMetrics.threatsDetected++;
    if (SECURITY_CONFIG.logAllThreats) {
      safeLogger.warn('File upload threat detected', {
        threats,
        filename: file.originalname || file.name,
      });
    }
    return { valid: false, threats };
  }
  return { valid: true };
}
/**
 * Comprehensive security validation
 */
export function validateSecurity(input, options = {}) {
  const config = { ...SECURITY_CONFIG, ...options };
  const threats = [];
  if (typeof input !== 'string') {
    input = JSON.stringify(input);
  }
  // Check input length
  if (input.length > config.maxInputLength) {
    threats.push({
      type: 'input_too_long',
      severity: 'medium',
      length: input.length,
      maxLength: config.maxInputLength,
    });
  }
  // Run all security checks
  const checks = [
    detectSqlInjection(input),
    detectXss(input),
    detectMaliciousPatterns(input),
    detectCommandInjection(input),
    detectPathTraversal(input),
  ];
  checks.forEach(check => {
    if (check.detected) {
      threats.push(...check.threats);
    }
  });
  if (threats.length > 0) {
    securityMetrics.threatsDetected++;
    const incident = {
      timestamp: new Date().toISOString(),
      threats,
      input: input.substring(0, 500),
      severity: threats.some(t => t.severity === 'high') ? 'high' : 'medium',
    };
    securityMetrics.securityIncidents.push(incident);
    // Keep only last 1000 incidents
    if (securityMetrics.securityIncidents.length > 1000) {
      securityMetrics.securityIncidents =
        securityMetrics.securityIncidents.slice(-1000);
    }
    if (config.logSecurityIncidents) {
      safeLogger.warn('Security incident detected', incident);
    }
    return { valid: false, threats, incident };
  }
  return { valid: true, threats: [] };
}
/**
 * Rate limiting validation
 */
export function validateRateLimit(identifier, type = 'general') {
  const now = Date.now();
  const key = `${type}:${identifier}`;
  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, {
      requests: [],
      blocked: false,
      blockUntil: 0,
    });
  }
  const record = rateLimitStore.get(key);
  // Check if currently blocked
  if (record.blocked && now < record.blockUntil) {
    securityMetrics.rateLimitViolations++;
    return {
      allowed: false,
      reason: 'rate_limited',
      retryAfter: record.blockUntil - now,
    };
  }
  // Remove old requests
  record.requests = record.requests.filter(time => now - time < 60000); // 1 minute
  // Check rate limits
  let limit;
  switch (type) {
  case 'login':
    limit = SECURITY_CONFIG.maxLoginAttempts;
    break;
  case 'signup':
    limit = SECURITY_CONFIG.maxSignupAttempts;
    break;
  case 'general':
    limit = SECURITY_CONFIG.maxRequestsPerMinute;
    break;
  default:
    limit = SECURITY_CONFIG.maxRequestsPerMinute;
  }
  if (record.requests.length >= limit) {
    record.blocked = true;
    record.blockUntil = now + 300000; // 5 minutes
    securityMetrics.rateLimitViolations++;
    safeLogger.warn('Rate limit exceeded', {
      identifier,
      type,
      limit,
      blockUntil: record.blockUntil,
    });
    return { allowed: false, reason: 'rate_limited', retryAfter: 300000 };
  }
  // Add current request
  record.requests.push(now);
  return { allowed: true };
}
/**
 * CSRF token validation
 */
export function validateCsrfToken(token, sessionToken) {
  if (!SECURITY_CONFIG.enableCsrfProtection) return { valid: true };
  if (!token || !sessionToken) {
    securityMetrics.csrfViolations++;
    safeLogger.warn('CSRF token missing', {
      hasToken: !!token,
      hasSessionToken: !!sessionToken,
    });
    return { valid: false, reason: 'missing_token' };
  }
  if (token !== sessionToken) {
    securityMetrics.csrfViolations++;
    safeLogger.warn('CSRF token mismatch', {
      tokenLength: token.length,
      sessionTokenLength: sessionToken.length,
    });
    return { valid: false, reason: 'token_mismatch' };
  }
  return { valid: true };
}
/**
 * Generate CSRF token
 */
export function generateCsrfToken() {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < SECURITY_CONFIG.csrfTokenLength; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}
/**
 * Input sanitization
 */
export function sanitizeInput(input, options = {}) {
  if (!SECURITY_CONFIG.enableInputSanitization) return input;
  const config = { ...SECURITY_CONFIG, ...options };
  if (typeof input !== 'string') return input;
  let sanitized = input;
  // Remove null bytes and control characters
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\u0000-\u001F\u007F]/g, '');
  // Strip scripts if enabled
  if (config.stripScripts) {
    sanitized = sanitized.replace(
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      '',
    );
  }
  // Strip styles if enabled
  if (config.stripStyles) {
    sanitized = sanitized.replace(
      /<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi,
      '',
    );
  }
  // Remove allowed HTML tags if specified
  if (config.allowedHtmlTags.length === 0) {
    sanitized = sanitized.replace(/<[^>]*>/g, '');
  } else {
    // Only allow specified tags
    const allowedTags = config.allowedHtmlTags.join('|');
    const regex = new RegExp(`<(?!/?)(?:${allowedTags})\b)[^>]+>`, 'gi');
    sanitized = sanitized.replace(regex, '');
  }
  // Normalize unicode
  sanitized = sanitized.normalize('NFC');
  // Trim whitespace
  sanitized = sanitized.trim();
  return sanitized;
}
/**
 * Get security metrics
 */
export function getSecurityMetrics() {
  return {
    ...securityMetrics,
    threatRate:
      securityMetrics.totalRequests > 0
        ? (securityMetrics.threatsDetected / securityMetrics.totalRequests) *
          100
        : 0,
    blockRate:
      securityMetrics.totalRequests > 0
        ? (securityMetrics.blockedRequests / securityMetrics.totalRequests) *
          100
        : 0,
    recentIncidents: securityMetrics.securityIncidents.slice(-10),
  };
}
/**
 * Reset security metrics
 */
export function resetSecurityMetrics() {
  Object.assign(securityMetrics, {
    totalRequests: 0,
    threatsDetected: 0,
    sqlInjectionAttempts: 0,
    xssAttempts: 0,
    csrfViolations: 0,
    rateLimitViolations: 0,
    fileUploadThreats: 0,
    commandInjectionAttempts: 0,
    pathTraversalAttempts: 0,
    maliciousPatterns: 0,
    blockedRequests: 0,
    securityIncidents: [],
  });
  rateLimitStore.clear();
}
/**
 * Update security configuration
 */
export function updateSecurityConfig(newConfig) {
  Object.assign(SECURITY_CONFIG, newConfig);
  safeLogger.info('Security configuration updated', { newConfig });
}
export default {
  validateSecurity,
  validateRateLimit,
  validateCsrfToken,
  validateFileUpload,
  generateCsrfToken,
  sanitizeInput,
  getSecurityMetrics,
  resetSecurityMetrics,
  updateSecurityConfig,
};
