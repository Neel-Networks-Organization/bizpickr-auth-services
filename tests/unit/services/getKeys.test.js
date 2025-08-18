import { jest } from "@jest/globals";
import fs from "fs";
import path from "path";
import { getPrivateKey, getPublicKey } from "../../../src/crypto/getKeys.js";
import { getCurrentKeyMeta } from "../../../src/crypto/keyManager.js";

// Mock dependencies
jest.mock("fs");
jest.mock("path");
jest.mock("../../../src/crypto/keyManager.js");

describe("GetKeys", () => {
  const mockKid = "test-kid-123";
  const mockPrivatePath = "/mock/keys/test-kid-123_private.pem";
  const mockPublicPath = "/mock/keys/test-kid-123_public.pem";
  const mockPrivatePem =
    "-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----";
  const mockPublicPem =
    "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY\n-----END PUBLIC KEY-----";

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock path.join
    path.join.mockImplementation((...args) => args.join("/"));

    // Mock process.cwd
    process.cwd = jest.fn().mockReturnValue("/mock");

    // Mock getCurrentKeyMeta
    getCurrentKeyMeta.mockReturnValue({
      kid: mockKid,
      private: `${mockKid}_private.pem`,
      public: `${mockKid}_public.pem`,
      createdAt: "2024-12-01T12:00:00.000Z",
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
    });

    // Mock fs.readFileSync
    fs.readFileSync.mockImplementation((filePath) => {
      if (filePath.includes("private")) {
        return mockPrivatePem;
      }
      if (filePath.includes("public")) {
        return mockPublicPem;
      }
      throw new Error("File not found");
    });
  });

  describe("getPrivateKey", () => {
    it("should return private key and kid when valid key exists", async () => {
      const result = await getPrivateKey();

      expect(getCurrentKeyMeta).toHaveBeenCalledTimes(1);
      expect(fs.readFileSync).toHaveBeenCalledWith(mockPrivatePath, "utf-8");
      expect(result).toHaveProperty("pirvateKey");
      expect(result).toHaveProperty("kid");
      expect(result.kid).toBe(mockKid);
    });

    it("should throw error when no current key meta exists", async () => {
      getCurrentKeyMeta.mockReturnValue(null);

      await expect(getPrivateKey()).rejects.toThrow(
        "No current private key found"
      );
    });

    it("should throw error when private key file does not exist", async () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error("ENOENT: no such file or directory");
      });

      await expect(getPrivateKey()).rejects.toThrow(
        "ENOENT: no such file or directory"
      );
    });

    it("should handle corrupted private key file", async () => {
      fs.readFileSync.mockReturnValue("corrupted-key-content");

      await expect(getPrivateKey()).rejects.toThrow();
    });

    it("should use correct file path for private key", async () => {
      await getPrivateKey();

      expect(path.join).toHaveBeenCalledWith(
        process.cwd(),
        "keys",
        `${mockKid}_private.pem`
      );
      expect(fs.readFileSync).toHaveBeenCalledWith(mockPrivatePath, "utf-8");
    });

    it("should handle different key IDs correctly", async () => {
      const differentKid = "different-kid-456";
      getCurrentKeyMeta.mockReturnValue({
        kid: differentKid,
        private: `${differentKid}_private.pem`,
        public: `${differentKid}_public.pem`,
      });

      await getPrivateKey();

      expect(fs.readFileSync).toHaveBeenCalledWith(
        `/mock/keys/${differentKid}_private.pem`,
        "utf-8"
      );
    });
  });

  describe("getPublicKey", () => {
    it("should return public key when valid key exists", async () => {
      const result = await getPublicKey();

      expect(getCurrentKeyMeta).toHaveBeenCalledTimes(1);
      expect(fs.readFileSync).toHaveBeenCalledWith(mockPublicPath, "utf-8");
      expect(result).toBeDefined();
    });

    it("should throw error when no current key meta exists", async () => {
      getCurrentKeyMeta.mockReturnValue(null);

      await expect(getPublicKey()).rejects.toThrow(
        "No current public key found"
      );
    });

    it("should throw error when public key file does not exist", async () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error("ENOENT: no such file or directory");
      });

      await expect(getPublicKey()).rejects.toThrow(
        "ENOENT: no such file or directory"
      );
    });

    it("should handle corrupted public key file", async () => {
      fs.readFileSync.mockReturnValue("corrupted-key-content");

      await expect(getPublicKey()).rejects.toThrow();
    });

    it("should use correct file path for public key", async () => {
      await getPublicKey();

      expect(path.join).toHaveBeenCalledWith(
        process.cwd(),
        "keys",
        `${mockKid}_public.pem`
      );
      expect(fs.readFileSync).toHaveBeenCalledWith(mockPublicPath, "utf-8");
    });

    it("should handle different key IDs correctly", async () => {
      const differentKid = "different-kid-456";
      getCurrentKeyMeta.mockReturnValue({
        kid: differentKid,
        private: `${differentKid}_private.pem`,
        public: `${differentKid}_public.pem`,
      });

      await getPublicKey();

      expect(fs.readFileSync).toHaveBeenCalledWith(
        `/mock/keys/${differentKid}_public.pem`,
        "utf-8"
      );
    });
  });

  describe("Key Import Process", () => {
    it("should import private key with RS256 algorithm", async () => {
      // Mock jose importPKCS8
      const mockImportPKCS8 = jest
        .fn()
        .mockResolvedValue({ type: "private", algorithm: "RS256" });
      jest.doMock("jose/key/import", () => ({
        importPKCS8: mockImportPKCS8,
      }));

      await getPrivateKey();

      expect(mockImportPKCS8).toHaveBeenCalledWith(mockPrivatePem, "RS256");
    });

    it("should import public key with RS256 algorithm", async () => {
      // Mock jose importSPKI
      const mockImportSPKI = jest
        .fn()
        .mockResolvedValue({ type: "public", algorithm: "RS256" });
      jest.doMock("jose/key/import", () => ({
        importSPKI: mockImportSPKI,
      }));

      await getPublicKey();

      expect(mockImportSPKI).toHaveBeenCalledWith(mockPublicPem, "RS256");
    });

    it("should handle import errors gracefully", async () => {
      const mockImportPKCS8 = jest
        .fn()
        .mockRejectedValue(new Error("Invalid key format"));
      jest.doMock("jose/key/import", () => ({
        importPKCS8: mockImportPKCS8,
      }));

      await expect(getPrivateKey()).rejects.toThrow("Invalid key format");
    });
  });

  describe("Error Handling", () => {
    it("should handle file system permission errors", async () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error("EACCES: permission denied");
      });

      await expect(getPrivateKey()).rejects.toThrow(
        "EACCES: permission denied"
      );
    });

    it("should handle file system read errors", async () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error("EBADF: bad file descriptor");
      });

      await expect(getPrivateKey()).rejects.toThrow(
        "EBADF: bad file descriptor"
      );
    });

    it("should handle empty key files", async () => {
      fs.readFileSync.mockReturnValue("");

      await expect(getPrivateKey()).rejects.toThrow();
    });

    it("should handle whitespace-only key files", async () => {
      fs.readFileSync.mockReturnValue("   \n   \t   ");

      await expect(getPrivateKey()).rejects.toThrow();
    });
  });

  describe("Key Validation", () => {
    it("should validate private key format", async () => {
      const validPrivatePem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
AgEAAoIBAQC7VJTUt9Us8cKB
-----END PRIVATE KEY-----`;

      fs.readFileSync.mockReturnValue(validPrivatePem);

      const result = await getPrivateKey();

      expect(result).toHaveProperty("pirvateKey");
      expect(result).toHaveProperty("kid");
    });

    it("should validate public key format", async () => {
      const validPublicPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7VJTUt9Us8cKB
AgEAAoIBAQC7VJTUt9Us8cKB
-----END PUBLIC KEY-----`;

      fs.readFileSync.mockReturnValue(validPublicPem);

      const result = await getPublicKey();

      expect(result).toBeDefined();
    });

    it("should reject invalid PEM format", async () => {
      const invalidPem = "INVALID_PEM_FORMAT";

      fs.readFileSync.mockReturnValue(invalidPem);

      await expect(getPrivateKey()).rejects.toThrow();
    });
  });

  describe("Concurrent Access", () => {
    it("should handle concurrent calls to getPrivateKey", async () => {
      const promises = [getPrivateKey(), getPrivateKey(), getPrivateKey()];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result).toHaveProperty("pirvateKey");
        expect(result).toHaveProperty("kid");
      });
    });

    it("should handle concurrent calls to getPublicKey", async () => {
      const promises = [getPublicKey(), getPublicKey(), getPublicKey()];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result).toBeDefined();
      });
    });
  });

  describe("Performance", () => {
    it("should cache key metadata calls efficiently", async () => {
      await getPrivateKey();
      await getPublicKey();

      // getCurrentKeyMeta should be called only once per function call
      expect(getCurrentKeyMeta).toHaveBeenCalledTimes(2);
    });

    it("should handle large key files", async () => {
      const largeKey =
        "-----BEGIN PRIVATE KEY-----\n" +
        "A".repeat(10000) +
        "\n-----END PRIVATE KEY-----";
      fs.readFileSync.mockReturnValue(largeKey);

      const startTime = Date.now();
      await getPrivateKey();
      const endTime = Date.now();

      // Should complete within reasonable time (less than 1 second)
      expect(endTime - startTime).toBeLessThan(1000);
    });
  });
});
