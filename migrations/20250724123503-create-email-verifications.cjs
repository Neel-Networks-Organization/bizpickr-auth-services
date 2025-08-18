"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable("email_verifications", {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      userId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: "auth_users", key: "id" },
        onDelete: "CASCADE",
        comment: "Associated user ID",
      },
      email: {
        type: Sequelize.STRING(255),
        allowNull: false,
        comment: "Email address to verify",
      },
      token: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true,
        comment: "Secure verification token",
      },
      tokenHash: {
        type: Sequelize.STRING(255),
        allowNull: false,
        comment: "Hashed version of the token for security",
      },
      verifiedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "When the email was verified",
      },
      ipAddress: {
        type: Sequelize.STRING(45),
        allowNull: true,
        comment: "IP address where verification was requested",
      },
      userAgent: {
        type: Sequelize.TEXT,
        allowNull: true,
        comment: "User agent of the request",
      },
      status: {
        type: Sequelize.ENUM("pending", "verified", "expired", "revoked"),
        defaultValue: "pending",
        comment: "Status of the verification token",
      },
      attempts: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
        comment: "Number of attempts to use this token",
      },
      maxAttempts: {
        type: Sequelize.INTEGER,
        defaultValue: 5,
        comment: "Maximum allowed attempts",
      },
      sentAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "When the verification email was sent",
      },
      emailProvider: {
        type: Sequelize.STRING(50),
        allowNull: true,
        comment: "Email service provider used",
      },
      emailId: {
        type: Sequelize.STRING(255),
        allowNull: true,
        comment: "Email provider's message ID",
      },
      expiresAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Token expiration time",
      },
      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Record update timestamp",
      },
      deletedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "Soft delete timestamp",
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Record creation timestamp",
      },
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable("email_verifications");
  },
};
