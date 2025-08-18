// src/config/utils.js
export const validateEnvType = (value, type, defaultValue = null) => {
  if (value === undefined || value === null) return defaultValue;
  switch (type) {
  case 'number': {
    const num = parseInt(value, 10);
    return isNaN(num) ? defaultValue : num;
  }
  case 'boolean': {
    return value === 'true' || value === '1';
  }
  case 'array': {
    return value.split(',').map(item => item.trim());
  }
  case 'url': {
    try {
      new URL(value);
      return value;
    } catch {
      return defaultValue;
    }
  }
  default:
    return value;
  }
};
