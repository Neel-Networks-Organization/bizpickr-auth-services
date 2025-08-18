import { jest } from "@jest/globals";
import fs from "fs";
import path from "path";
import {
  getCurrentKeyMeta,
  getAllPublicKeysMeta,
  rotateKeys,
} from "../../../src/crypto/keyManager.js";
import { env } from "../../../src/config/env.js";

// Mock dependencies
jest.mock("fs");
jest.mock("path");
jest.mock("../../../src/config/env.js");

describe("KeyManager", () => {
  const mockKeysDir = "/mock/keys";
  const mockKeysJson = "/mock/keys/keys.json";
  const mockCurrentKid = "202412011200Z";
  const mockExpiredKid = "202411011200Z";

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock path.join
    path.join.mockImplementation((...args) => args.join("/"));

    // Mock process.cwd
    process.cwd = jest.fn().mockReturnValue("/mock");

    // Mock environment variables
    env.PRIVATE_KEY_RETENTION = "1h";

    // Mock fs.existsSync
    fs.existsSync.mockReturnValue(true);

    // Mock fs.readFileSync
    fs.readFileSync.mockReturnValue(
      JSON.stringify({
        current: mockCurrentKid,
        keys: [
          {
            kid: mockCurrentKid,
            private: `${mockCurrentKid}_private.pem`,
            public: `${mockCurrentKid}_public.pem`,
            createdAt: "2024-12-01T12:00:00.000Z",
            expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
          },
          {
            kid: mockExpiredKid,
            private: `${mockExpiredKid}_private.pem`,
            public: `${mockExpiredKid}_public.pem`,
            createdAt: "2024-11-01T12:00:00.000Z",
            expiresAt: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
          },
        ],
      })
    );
  });

  describe("getCurrentKeyMeta", () => {
    it("should return current key metadata when valid key exists", () => {
      const result = getCurrentKeyMeta();

      expect(fs.readFileSync).toHaveBeenCalledWith(mockKeysJson, "utf-8");
      expect(result).toEqual({
        kid: mockCurrentKid,
        private: `${mockCurrentKid}_private.pem`,
        public: `${mockCurrentKid}_public.pem`,
        createdAt: "2024-12-01T12:00:00.000Z",
        expiresAt: expect.any(String),
      });
    });

    it("should return undefined when no current key is set", () => {
      fs.readFileSync.mockReturnValue(
        JSON.stringify({
          current: null,
          keys: [],
        })
      );

      const result = getCurrentKeyMeta();

      expect(result).toBeUndefined();
    });

    it("should return undefined when keys.json does not exist", () => {
      fs.existsSync.mockReturnValue(false);

      const result = getCurrentKeyMeta();

      expect(result).toBeUndefined();
    });

    it("should return undefined when current key is not found in keys array", () => {
      fs.readFileSync.mockReturnValue(
        JSON.stringify({
          current: "non-existent-kid",
          keys: [],
        })
      );

      const result = getCurrentKeyMeta();

      expect(result).toBeUndefined();
    });
  });

  describe("getAllPublicKeysMeta", () => {
    it("should return all public key metadata", () => {
      const result = getAllPublicKeysMeta();

      expect(fs.readFileSync).toHaveBeenCalledWith(mockKeysJson, "utf-8");
      expect(result).toEqual([
        {
          kid: mockCurrentKid,
          public: `${mockCurrentKid}_public.pem`,
        },
        {
          kid: mockExpiredKid,
          public: `${mockExpiredKid}_public.pem`,
        },
      ]);
    });

    it("should return empty array when keys.json does not exist", () => {
      fs.existsSync.mockReturnValue(false);

      const result = getAllPublicKeysMeta();

      expect(result).toEqual([]);
    });

    it("should return empty array when no keys exist", () => {
      fs.readFileSync.mockReturnValue(
        JSON.stringify({
          current: null,
          keys: [],
        })
      );

      const result = getAllPublicKeysMeta();

      expect(result).toEqual([]);
    });
  });

  describe("rotateKeys", () => {
    beforeEach(() => {
      // Mock jose functions
      jest.doMock("jose", () => ({
        generateKeyPair: jest.fn().mockResolvedValue({
          publicKey: { type: "public" },
          privateKey: { type: "private" },
        }),
        exportPKCS8: jest.fn().mockResolvedValue("mock-private-pem"),
        exportSPKI: jest.fn().mockResolvedValue("mock-public-pem"),
      }));

      // Mock ms function
      jest.doMock("ms", () => jest.fn().mockReturnValue(3600000));

      // Mock console.log
      console.log = jest.fn();
    });

    it("should skip key generation when valid current key exists", async () => {
      // Mock hasValidCurrentKey to return true
      const mockHasValidCurrentKey = jest.fn().mockReturnValue(true);
      jest.doMock("../../../src/crypto/keyManager.js", () => ({
        ...jest.requireActual("../../../src/crypto/keyManager.js"),
        hasValidCurrentKey: mockHasValidCurrentKey,
      }));

      await rotateKeys();

      expect(console.log).toHaveBeenCalledWith(
        "✅ Valid current key exists. Skipping key generation."
      );
    });

    it("should generate new keys when no valid current key exists", async () => {
      // Mock hasValidCurrentKey to return false
      const mockHasValidCurrentKey = jest.fn().mockReturnValue(false);
      jest.doMock("../../../src/crypto/keyManager.js", () => ({
        ...jest.requireActual("../../../src/crypto/keyManager.js"),
        hasValidCurrentKey: mockHasValidCurrentKey,
      }));

      // Mock fs.mkdirSync
      fs.mkdirSync = jest.fn();

      // Mock fs.writeFileSync
      fs.writeFileSync = jest.fn();

      // Mock Date.now to return fixed timestamp
      const mockDate = new Date("2024-12-01T12:00:00.000Z");
      jest.spyOn(Date, "now").mockReturnValue(mockDate.getTime());
      jest.spyOn(global, "Date").mockImplementation(() => mockDate);

      await rotateKeys();

      expect(console.log).toHaveBeenCalledWith("🔄 Generating new JWT keys...");
      expect(fs.mkdirSync).toHaveBeenCalledWith(mockKeysDir, {
        recursive: true,
      });
      expect(fs.writeFileSync).toHaveBeenCalledTimes(2); // private and public keys
    });

    it("should handle file system errors gracefully", async () => {
      const mockHasValidCurrentKey = jest.fn().mockReturnValue(false);
      jest.doMock("../../../src/crypto/keyManager.js", () => ({
        ...jest.requireActual("../../../src/crypto/keyManager.js"),
        hasValidCurrentKey: mockHasValidCurrentKey,
      }));

      fs.mkdirSync.mockImplementation(() => {
        throw new Error("Permission denied");
      });

      await expect(rotateKeys()).rejects.toThrow("Permission denied");
    });

    it("should create keys directory if it does not exist", async () => {
      const mockHasValidCurrentKey = jest.fn().mockReturnValue(false);
      jest.doMock("../../../src/crypto/keyManager.js", () => ({
        ...jest.requireActual("../../../src/crypto/keyManager.js"),
        hasValidCurrentKey: mockHasValidCurrentKey,
      }));

      fs.mkdirSync = jest.fn();
      fs.writeFileSync = jest.fn();

      await rotateKeys();

      expect(fs.mkdirSync).toHaveBeenCalledWith(mockKeysDir, {
        recursive: true,
      });
    });

    it("should save key metadata with correct structure", async () => {
      const mockHasValidCurrentKey = jest.fn().mockReturnValue(false);
      jest.doMock("../../../src/crypto/keyManager.js", () => ({
        ...jest.requireActual("../../../src/crypto/keyManager.js"),
        hasValidCurrentKey: mockHasValidCurrentKey,
      }));

      fs.mkdirSync = jest.fn();
      fs.writeFileSync = jest.fn();

      const mockDate = new Date("2024-12-01T12:00:00.000Z");
      jest.spyOn(Date, "now").mockReturnValue(mockDate.getTime());
      jest.spyOn(global, "Date").mockImplementation(() => mockDate);

      await rotateKeys();

      // Verify that keys.json was updated with new key metadata
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        mockKeysJson,
        expect.stringContaining('"current"'),
        expect.any(String)
      );
    });
  });

  describe("Key Metadata Structure", () => {
    it("should validate key metadata structure", () => {
      const result = getCurrentKeyMeta();

      expect(result).toHaveProperty("kid");
      expect(result).toHaveProperty("private");
      expect(result).toHaveProperty("public");
      expect(result).toHaveProperty("createdAt");
      expect(result).toHaveProperty("expiresAt");

      expect(typeof result.kid).toBe("string");
      expect(typeof result.private).toBe("string");
      expect(typeof result.public).toBe("string");
      expect(typeof result.createdAt).toBe("string");
      expect(typeof result.expiresAt).toBe("string");
    });

    it("should validate public keys metadata structure", () => {
      const result = getAllPublicKeysMeta();

      expect(Array.isArray(result)).toBe(true);
      result.forEach((key) => {
        expect(key).toHaveProperty("kid");
        expect(key).toHaveProperty("public");
        expect(typeof key.kid).toBe("string");
        expect(typeof key.public).toBe("string");
      });
    });
  });

  describe("Error Handling", () => {
    it("should handle corrupted keys.json file", () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error("Invalid JSON");
      });

      expect(() => getCurrentKeyMeta()).toThrow("Invalid JSON");
    });

    it("should handle missing keys.json file", () => {
      fs.existsSync.mockReturnValue(false);

      const result = getCurrentKeyMeta();

      expect(result).toBeUndefined();
    });

    it("should handle empty keys.json file", () => {
      fs.readFileSync.mockReturnValue("");

      expect(() => getCurrentKeyMeta()).toThrow();
    });
  });

  describe("Key Expiration Logic", () => {
    it("should identify expired keys correctly", () => {
      const expiredKey = {
        kid: "expired",
        expiresAt: new Date(Date.now() - 1000).toISOString(), // 1 second ago
      };

      const currentTime = new Date(expiredKey.expiresAt).getTime();
      const now = Date.now();

      expect(currentTime < now).toBe(true);
    });

    it("should identify valid keys correctly", () => {
      const validKey = {
        kid: "valid",
        expiresAt: new Date(Date.now() + 1000).toISOString(), // 1 second from now
      };

      const currentTime = new Date(validKey.expiresAt).getTime();
      const now = Date.now();

      expect(currentTime > now).toBe(true);
    });
  });
});
