"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable("password_resets", {
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
      token: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true,
        comment: "Secure reset token",
      },
      tokenHash: {
        type: Sequelize.STRING(255),
        allowNull: false,
        comment: "Hashed version of the token for security",
      },
      expiresAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Token expiration time",
      },
      usedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "When the token was used",
      },
      ipAddress: {
        type: Sequelize.STRING(45),
        allowNull: true,
        comment: "IP address where reset was requested",
      },
      userAgent: {
        type: Sequelize.TEXT,
        allowNull: true,
        comment: "User agent of the request",
      },
      status: {
        type: Sequelize.ENUM("pending", "used", "expired", "revoked"),
        defaultValue: "pending",
        comment: "Status of the reset token",
      },
      attempts: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
        comment: "Number of attempts to use this token",
      },
      maxAttempts: {
        type: Sequelize.INTEGER,
        defaultValue: 3,
        comment: "Maximum allowed attempts",
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Record creation timestamp",
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
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable("password_resets");
  },
};
