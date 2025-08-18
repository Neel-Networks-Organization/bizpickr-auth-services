import { jest } from "@jest/globals";
import { Buffer } from "buffer";

// Set dummy env vars for tests to avoid process.exit(1)
beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.PORT = "3001";
  process.env.JWT_SECRET = "test";
  process.env.REFRESH_TOKEN_SECRET = "test";
  process.env.DB_HOST = "localhost";
  process.env.DB_NAME = "test";
  process.env.DB_USER = "test";
  process.env.DB_PASSWORD = "test";
  process.env.REDIS_HOST = "localhost";
  process.env.REDIS_PORT = "6379";
});

// Global test setup
global.jest = jest;

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Global test timeout
jest.setTimeout(10000);

// Mock crypto for consistent testing
Object.defineProperty(global, "crypto", {
  value: {
    getRandomValues: jest.fn((arr) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
      }
      return arr;
    }),
    subtle: {
      generateKey: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(),
    },
  },
});

// Mock TextEncoder/TextDecoder
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock Buffer if not available
if (typeof global.Buffer === "undefined") {
  global.Buffer = Buffer;
}

// Mock process.cwd
process.cwd = jest.fn(() => "/mock/workspace");

// Mock Date.now for consistent timestamps
const mockDate = new Date("2024-12-01T12:00:00.000Z");
jest.spyOn(Date, "now").mockReturnValue(mockDate.getTime());

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
  jest.clearAllTimers();
});
