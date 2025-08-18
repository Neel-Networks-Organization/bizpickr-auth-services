import { jest } from "@jest/globals";
import {
  validateEmail,
  validateEmailFormat,
  sanitizeEmail,
} from "../../../src/validators/emailValidation.js";

describe("Email Validation", () => {
  describe("validateEmail", () => {
    it("should validate correct email addresses", () => {
      const validEmails = [
        "test@example.com",
        "user.name@domain.co.uk",
        "user+tag@example.org",
        "user123@test-domain.com",
        "user@subdomain.example.com",
        "user@example.io",
        "user@example.net",
        "user@example.edu",
        "user@example.gov",
        "user@example.museum",
      ];

      validEmails.forEach((email) => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    it("should reject invalid email addresses", () => {
      const invalidEmails = [
        "invalid-email",
        "@example.com",
        "user@",
        "user@.com",
        "user..name@example.com",
        "user@example..com",
        "user name@example.com",
        "user@example",
        "user@.example.com",
        "user@example.",
        "user@@example.com",
        "user@example@com",
        "user@example.com.",
        ".user@example.com",
        "user@-example.com",
        "user@example-.com",
        "user@example.com-",
        "-user@example.com",
        "user-@example.com",
      ];

      invalidEmails.forEach((email) => {
        expect(validateEmail(email)).toBe(false);
      });
    });

    it("should handle edge cases", () => {
      expect(validateEmail("")).toBe(false);
      expect(validateEmail(null)).toBe(false);
      expect(validateEmail(undefined)).toBe(false);
      expect(validateEmail("   ")).toBe(false);
      expect(validateEmail("a@b.c")).toBe(true); // Minimal valid email
    });

    it("should handle special characters in local part", () => {
      const specialCharEmails = [
        "user+tag@example.com",
        "user.tag@example.com",
        "user_tag@example.com",
        "user-tag@example.com",
        "user%tag@example.com",
        "user!tag@example.com",
        "user#tag@example.com",
        "user$tag@example.com",
        "user&tag@example.com",
        "user*tag@example.com",
        "user=tag@example.com",
        "user?tag@example.com",
        "user^tag@example.com",
        "user|tag@example.com",
        "user~tag@example.com",
      ];

      specialCharEmails.forEach((email) => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    it("should handle international domain names", () => {
      const internationalEmails = [
        "user@example.co.uk",
        "user@example.com.au",
        "user@example.org.uk",
        "user@example.net.au",
        "user@example.gov.uk",
        "user@example.ac.uk",
      ];

      internationalEmails.forEach((email) => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    it("should handle subdomains", () => {
      const subdomainEmails = [
        "user@sub.example.com",
        "user@sub.sub.example.com",
        "user@sub-domain.example.com",
        "user@sub_domain.example.com",
      ];

      subdomainEmails.forEach((email) => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    it("should handle long but valid emails", () => {
      const longEmail = "a".repeat(64) + "@" + "b".repeat(63) + ".com";
      expect(validateEmail(longEmail)).toBe(true);
    });

    it("should reject emails that are too long", () => {
      const tooLongEmail = "a".repeat(65) + "@" + "b".repeat(63) + ".com";
      expect(validateEmail(tooLongEmail)).toBe(false);
    });
  });

  describe("validateEmailFormat", () => {
    it("should validate email format with detailed error messages", () => {
      const testCases = [
        {
          email: "test@example.com",
          expected: { isValid: true, errors: [] },
        },
        {
          email: "invalid-email",
          expected: {
            isValid: false,
            errors: ["Invalid email format"],
          },
        },
        {
          email: "@example.com",
          expected: {
            isValid: false,
            errors: ["Local part cannot be empty"],
          },
        },
        {
          email: "user@",
          expected: {
            isValid: false,
            errors: ["Domain cannot be empty"],
          },
        },
        {
          email: "user@.com",
          expected: {
            isValid: false,
            errors: ["Domain cannot start with a dot"],
          },
        },
        {
          email: "user@example.",
          expected: {
            isValid: false,
            errors: ["Domain cannot end with a dot"],
          },
        },
        {
          email: "user..name@example.com",
          expected: {
            isValid: false,
            errors: ["Local part cannot contain consecutive dots"],
          },
        },
        {
          email: "user@example..com",
          expected: {
            isValid: false,
            errors: ["Domain cannot contain consecutive dots"],
          },
        },
        {
          email: "user name@example.com",
          expected: {
            isValid: false,
            errors: ["Local part cannot contain spaces"],
          },
        },
        {
          email: "user@example@com",
          expected: {
            isValid: false,
            errors: ["Email can only contain one @ symbol"],
          },
        },
      ];

      testCases.forEach(({ email, expected }) => {
        const result = validateEmailFormat(email);
        expect(result.isValid).toBe(expected.isValid);
        expect(result.errors).toEqual(expected.errors);
      });
    });

    it("should handle multiple validation errors", () => {
      const email = "user..name@example..com";
      const result = validateEmailFormat(email);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain(
        "Local part cannot contain consecutive dots"
      );
      expect(result.errors).toContain("Domain cannot contain consecutive dots");
    });

    it("should handle edge cases with detailed validation", () => {
      const testCases = [
        {
          email: "",
          expected: { isValid: false, errors: ["Email cannot be empty"] },
        },
        {
          email: null,
          expected: {
            isValid: false,
            errors: ["Email cannot be null or undefined"],
          },
        },
        {
          email: undefined,
          expected: {
            isValid: false,
            errors: ["Email cannot be null or undefined"],
          },
        },
        {
          email: "   ",
          expected: { isValid: false, errors: ["Email cannot be empty"] },
        },
      ];

      testCases.forEach(({ email, expected }) => {
        const result = validateEmailFormat(email);
        expect(result.isValid).toBe(expected.isValid);
        expect(result.errors).toEqual(expected.errors);
      });
    });

    it("should validate email length constraints", () => {
      const testCases = [
        {
          email: "a@b.c",
          expected: { isValid: true, errors: [] },
        },
        {
          email: "a".repeat(65) + "@example.com",
          expected: {
            isValid: false,
            errors: ["Local part cannot exceed 64 characters"],
          },
        },
        {
          email: "user@" + "a".repeat(64) + ".com",
          expected: {
            isValid: false,
            errors: ["Domain cannot exceed 63 characters"],
          },
        },
        {
          email: "user@example." + "a".repeat(64),
          expected: {
            isValid: false,
            errors: ["Top-level domain cannot exceed 63 characters"],
          },
        },
      ];

      testCases.forEach(({ email, expected }) => {
        const result = validateEmailFormat(email);
        expect(result.isValid).toBe(expected.isValid);
        expect(result.errors).toEqual(expected.errors);
      });
    });
  });

  describe("sanitizeEmail", () => {
    it("should sanitize email addresses correctly", () => {
      const testCases = [
        {
          input: "  TEST@EXAMPLE.COM  ",
          expected: "test@example.com",
        },
        {
          input: "User.Name@Domain.Com",
          expected: "user.name@domain.com",
        },
        {
          input: "USER+TAG@EXAMPLE.ORG",
          expected: "user+tag@example.org",
        },
        {
          input: "user@example.com",
          expected: "user@example.com",
        },
        {
          input: "  user@example.com  ",
          expected: "user@example.com",
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(sanitizeEmail(input)).toBe(expected);
      });
    });

    it("should handle edge cases in sanitization", () => {
      expect(sanitizeEmail("")).toBe("");
      expect(sanitizeEmail("   ")).toBe("");
      expect(sanitizeEmail(null)).toBe("");
      expect(sanitizeEmail(undefined)).toBe("");
    });

    it("should preserve special characters in local part", () => {
      const testCases = [
        "user+tag@example.com",
        "user.tag@example.com",
        "user_tag@example.com",
        "user-tag@example.com",
        "user%tag@example.com",
        "user!tag@example.com",
        "user#tag@example.com",
        "user$tag@example.com",
        "user&tag@example.com",
        "user*tag@example.com",
        "user=tag@example.com",
        "user?tag@example.com",
        "user^tag@example.com",
        "user|tag@example.com",
        "user~tag@example.com",
      ];

      testCases.forEach((email) => {
        const sanitized = sanitizeEmail(email.toUpperCase());
        expect(sanitized).toBe(email);
      });
    });

    it("should handle mixed case domains", () => {
      const testCases = [
        {
          input: "user@EXAMPLE.COM",
          expected: "user@example.com",
        },
        {
          input: "user@Example.Com",
          expected: "user@example.com",
        },
        {
          input: "user@SUB.EXAMPLE.COM",
          expected: "user@sub.example.com",
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(sanitizeEmail(input)).toBe(expected);
      });
    });
  });

  describe("Integration Tests", () => {
    it("should work together: sanitize then validate", () => {
      const dirtyEmail = "  USER.NAME@EXAMPLE.COM  ";
      const sanitized = sanitizeEmail(dirtyEmail);
      const isValid = validateEmail(sanitized);

      expect(sanitized).toBe("user.name@example.com");
      expect(isValid).toBe(true);
    });

    it("should work together: sanitize then validate format", () => {
      const dirtyEmail = "  USER.NAME@EXAMPLE.COM  ";
      const sanitized = sanitizeEmail(dirtyEmail);
      const formatResult = validateEmailFormat(sanitized);

      expect(sanitized).toBe("user.name@example.com");
      expect(formatResult.isValid).toBe(true);
      expect(formatResult.errors).toEqual([]);
    });

    it("should handle invalid emails through the entire pipeline", () => {
      const invalidEmail = "  INVALID-EMAIL  ";
      const sanitized = sanitizeEmail(invalidEmail);
      const isValid = validateEmail(sanitized);
      const formatResult = validateEmailFormat(sanitized);

      expect(sanitized).toBe("invalid-email");
      expect(isValid).toBe(false);
      expect(formatResult.isValid).toBe(false);
      expect(formatResult.errors).toContain("Invalid email format");
    });
  });

  describe("Performance Tests", () => {
    it("should handle large numbers of email validations efficiently", () => {
      const emails = [
        "test1@example.com",
        "test2@example.org",
        "test3@example.net",
        "invalid-email-1",
        "invalid-email-2",
        "user@example.com",
        "admin@example.org",
      ];

      const startTime = Date.now();

      for (let i = 0; i < 1000; i++) {
        emails.forEach((email) => {
          validateEmail(email);
          validateEmailFormat(email);
          sanitizeEmail(email);
        });
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (less than 1 second)
      expect(duration).toBeLessThan(1000);
    });

    it("should handle very long email addresses efficiently", () => {
      const longEmail = "a".repeat(64) + "@" + "b".repeat(63) + ".com";

      const startTime = Date.now();

      for (let i = 0; i < 100; i++) {
        validateEmail(longEmail);
        validateEmailFormat(longEmail);
        sanitizeEmail(longEmail);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (less than 100ms)
      expect(duration).toBeLessThan(100);
    });
  });

  describe("Security Tests", () => {
    it("should not be vulnerable to regex DoS attacks", () => {
      const maliciousEmail = "a".repeat(1000) + "@" + "b".repeat(1000) + ".com";

      const startTime = Date.now();
      const result = validateEmail(maliciousEmail);
      const endTime = Date.now();

      // Should complete quickly and return false
      expect(endTime - startTime).toBeLessThan(100);
      expect(result).toBe(false);
    });

    it("should handle emails with many special characters", () => {
      const specialCharEmail = "user" + "!".repeat(100) + "@example.com";

      const startTime = Date.now();
      const result = validateEmail(specialCharEmail);
      const endTime = Date.now();

      // Should complete quickly
      expect(endTime - startTime).toBeLessThan(100);
      expect(result).toBe(true);
    });

    it("should handle emails with many dots", () => {
      const dotEmail = "user" + ".".repeat(50) + "name@example.com";

      const startTime = Date.now();
      const result = validateEmail(dotEmail);
      const endTime = Date.now();

      // Should complete quickly and return false
      expect(endTime - startTime).toBeLessThan(100);
      expect(result).toBe(false);
    });
  });

  describe("Edge Cases", () => {
    it("should handle emails with all possible special characters", () => {
      const specialChars = "!#$%&'*+-/=?^_`{|}~";
      const email = `user${specialChars}@example.com`;

      expect(validateEmail(email)).toBe(true);
    });

    it("should handle emails with numbers in all parts", () => {
      const email = "user123@example456.com789";

      expect(validateEmail(email)).toBe(true);
    });

    it("should handle emails with hyphens in domain", () => {
      const email = "user@example-domain.com";

      expect(validateEmail(email)).toBe(true);
    });

    it("should handle emails with hyphens at domain boundaries", () => {
      const validEmail = "user@example-domain.com";
      const invalidEmail1 = "user@-example.com";
      const invalidEmail2 = "user@example-.com";

      expect(validateEmail(validEmail)).toBe(true);
      expect(validateEmail(invalidEmail1)).toBe(false);
      expect(validateEmail(invalidEmail2)).toBe(false);
    });

    it("should handle emails with multiple dots in domain", () => {
      const validEmail = "user@sub.example.com";
      const invalidEmail = "user@sub..example.com";

      expect(validateEmail(validEmail)).toBe(true);
      expect(validateEmail(invalidEmail)).toBe(false);
    });
  });
});
