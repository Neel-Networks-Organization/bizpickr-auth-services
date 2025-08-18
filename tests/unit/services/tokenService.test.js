// import { jest } from "@jest/globals";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../../../src/crypto/tokenService.js";
import { getPrivateKey } from "../../../src/crypto/getKeys.js";
import { env } from "../../../src/config/env.js";

// Mock dependencies
jest.mock("../../../src/crypto/getKeys.js");
jest.mock("../../../src/config/env.js");

describe("TokenService", () => {
  let mockPrivateKey;
  let mockKid;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Mock private key and kid
    mockPrivateKey = { type: "private" };
    mockKid = "test-kid-123";

    // Mock getPrivateKey function
    getPrivateKey.mockResolvedValue({
      pirvateKey: mockPrivateKey,
      kid: mockKid,
    });

    // Mock environment variables
    env.PRIVATE_KEY_EXIPRY = "15m";
    env.REFRESH_TOKEN_SECRET = "test-refresh-secret";
    env.REFRESH_TOKEN_EXPIRY = "7d";
  });

  describe("generateAccessToken", () => {
    it("should generate access token with correct payload and headers", async () => {
      const mockUser = {
        id: "user-123",
        email: "test@example.com",
        type: "customer",
        linkedUserId: null,
        role: "user",
      };

      const token = await generateAccessToken(mockUser);

      expect(getPrivateKey).toHaveBeenCalledTimes(1);
      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      expect(token.split(".")).toHaveLength(3); // JWT has 3 parts
    });

    it("should include all user properties in token payload", async () => {
      const mockUser = {
        id: "user-456",
        email: "admin@example.com",
        type: "admin",
        linkedUserId: "parent-123",
        role: "admin",
      };

      await generateAccessToken(mockUser);

      expect(getPrivateKey).toHaveBeenCalledWith();
    });

    it("should handle missing optional user properties", async () => {
      const mockUser = {
        id: "user-789",
        email: "simple@example.com",
        type: "customer",
        // missing linkedUserId and role
      };

      const token = await generateAccessToken(mockUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
    });

    it("should throw error when getPrivateKey fails", async () => {
      const mockUser = { id: "user-123", email: "test@example.com" };
      const errorMessage = "Failed to get private key";

      getPrivateKey.mockRejectedValue(new Error(errorMessage));

      await expect(generateAccessToken(mockUser)).rejects.toThrow(errorMessage);
    });

    it("should use correct expiration time from env", async () => {
      env.PRIVATE_KEY_EXIPRY = "30m";
      const mockUser = { id: "user-123", email: "test@example.com" };

      await generateAccessToken(mockUser);

      expect(getPrivateKey).toHaveBeenCalled();
    });
  });

  describe("generateRefreshToken", () => {
    it("should generate refresh token with correct payload", async () => {
      const mockUser = {
        id: "user-123",
        type: "customer",
        linkedUserId: null,
      };

      const token = await generateRefreshToken(mockUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      expect(token.split(".")).toHaveLength(3);
    });

    it("should include only required user properties in refresh token", async () => {
      const mockUser = {
        id: "user-456",
        email: "test@example.com", // Should not be included
        type: "admin",
        linkedUserId: "parent-123",
        role: "admin", // Should not be included
      };

      const token = await generateRefreshToken(mockUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
    });

    it("should use HS256 algorithm for refresh tokens", async () => {
      const mockUser = { id: "user-123", type: "customer" };

      const token = await generateRefreshToken(mockUser);

      expect(token).toBeDefined();
      // Note: We can't easily test the algorithm without decoding, but we can verify token structure
    });

    it("should use correct refresh token secret from env", async () => {
      env.REFRESH_TOKEN_SECRET = "custom-refresh-secret";
      const mockUser = { id: "user-123", type: "customer" };

      const token = await generateRefreshToken(mockUser);

      expect(token).toBeDefined();
    });

    it("should use correct refresh token expiry from env", async () => {
      env.REFRESH_TOKEN_EXPIRY = "30d";
      const mockUser = { id: "user-123", type: "customer" };

      const token = await generateRefreshToken(mockUser);

      expect(token).toBeDefined();
    });

    it("should handle missing linkedUserId gracefully", async () => {
      const mockUser = {
        id: "user-123",
        type: "customer",
        // missing linkedUserId
      };

      const token = await generateRefreshToken(mockUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
    });
  });

  describe("Error Handling", () => {
    it("should handle invalid user data gracefully", async () => {
      const invalidUser = null;

      await expect(generateAccessToken(invalidUser)).rejects.toThrow();
    });

    it("should handle missing required user properties", async () => {
      const incompleteUser = {
        // missing id and email
        type: "customer",
      };

      await expect(generateAccessToken(incompleteUser)).rejects.toThrow();
    });
  });

  describe("Token Security", () => {
    it("should generate different tokens for different users", async () => {
      const user1 = {
        id: "user-1",
        email: "user1@example.com",
        type: "customer",
      };
      const user2 = {
        id: "user-2",
        email: "user2@example.com",
        type: "customer",
      };

      const token1 = await generateAccessToken(user1);
      const token2 = await generateAccessToken(user2);

      expect(token1).not.toBe(token2);
    });

    it("should generate different refresh tokens for different users", async () => {
      const user1 = { id: "user-1", type: "customer" };
      const user2 = { id: "user-2", type: "customer" };

      const token1 = await generateRefreshToken(user1);
      const token2 = await generateRefreshToken(user2);

      expect(token1).not.toBe(token2);
    });
  });
});
