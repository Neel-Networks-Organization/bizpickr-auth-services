import { describe, it, expect } from '@jest/globals';

describe('Simple Test Suite', () => {
  it('should pass a basic test', () => {
    expect(1 + 1).toBe(2);
  });

  it('should handle ES modules', () => {
    const testValue = 'Hello ES Modules';
    expect(testValue).toBe('Hello ES Modules');
  });

  it('should work with async/await', async () => {
    const result = await Promise.resolve('async result');
    expect(result).toBe('async result');
  });
});
