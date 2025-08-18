/**
 * API Versioning Middleware
 * Supports both header-based and URL-based versioning
 */

export const apiVersioning = (req, res, next) => {
  // Check for API version in headers
  const headerVersion =
    req.headers['api-version'] || req.headers['x-api-version'];

  // Check for API version in URL path
  const urlVersion = req.path.match(/\/api\/v(\d+)/)?.[1];

  // Determine the API version
  const version = headerVersion || urlVersion || 'v1';

  // Validate version format
  if (!/^v\d+$/.test(version)) {
    return res.status(400).json({
      error: {
        message: 'Invalid API version format. Use format: v1, v2, etc.',
        code: 'INVALID_API_VERSION',
        supportedVersions: ['v1', 'v2'],
      },
    });
  }

  // Set version in request object
  req.apiVersion = version;
  req.apiVersionNumber = parseInt(version.substring(1));

  // Add version info to response headers
  res.set('X-API-Version', version);
  res.set('X-API-Version-Supported', 'v1, v2');

  next();
};

export const requireApiVersion = (minVersion = 1) => {
  return (req, res, next) => {
    const versionNumber = req.apiVersionNumber || 1;

    if (versionNumber < minVersion) {
      return res.status(400).json({
        error: {
          message: `API version ${req.apiVersion} is not supported. Minimum required: v${minVersion}`,
          code: 'UNSUPPORTED_API_VERSION',
          requiredVersion: `v${minVersion}`,
          currentVersion: req.apiVersion,
        },
      });
    }

    next();
  };
};
