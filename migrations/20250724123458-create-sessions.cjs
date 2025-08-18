"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable("sessions", {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        comment: "Unique session identifier",
      },
      userId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: "auth_users", key: "id" },
        onDelete: "CASCADE",
        comment: "Associated user ID",
      },
      sessionToken: {
        type: Sequelize.STRING(512),
        allowNull: false,
        unique: true,
        comment: "Session token for authentication",
      },
      refreshToken: {
        type: Sequelize.STRING(512),
        allowNull: true,
        unique: true,
        comment: "Refresh token for session renewal",
      },
      isActive: {
        type: Sequelize.BOOLEAN,
        defaultValue: true,
        comment: "Session active status",
      },
      expiresAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Session expiration timestamp",
      },
      invalidatedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "Session invalidation timestamp",
      },
      invalidationReason: {
        type: Sequelize.STRING(100),
        allowNull: true,
        comment: "Reason for session invalidation",
      },
      userAgent: {
        type: Sequelize.TEXT,
        allowNull: true,
        comment: "User agent string",
      },
      ipAddress: {
        type: Sequelize.STRING(45),
        allowNull: true,
        comment: "IP address of session",
      },
      deviceInfo: {
        type: Sequelize.JSON,
        allowNull: true,
        comment: "Device information",
      },
      locationInfo: {
        type: Sequelize.JSON,
        allowNull: true,
        comment: "Geographic location information",
      },
      lastActivityAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "Last activity timestamp",
      },
      loginAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "Login timestamp",
      },
      logoutAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "Logout timestamp",
      },
      refreshTokenExpiresAt: {
        type: Sequelize.DATE,
        allowNull: true,
        comment: "Refresh token expiration",
      },
      securityEvents: {
        type: Sequelize.JSON,
        allowNull: true,
        defaultValue: [],
        comment: "Security events for this session",
      },
      metadata: {
        type: Sequelize.JSON,
        allowNull: true,
        defaultValue: {},
        comment: "Additional session metadata",
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        comment: "Record creation timestamp",
      },
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable("sessions");
  },
};
