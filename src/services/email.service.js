/**
 * Email Service - Email Sending and Templates
 *
 * Handles email functionality:
 * - Send emails via various providers
 * - Email templates
 * - Email tracking and delivery
 */
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';

class EmailService {
  constructor() {
    this.provider = process.env.EMAIL_PROVIDER || 'nodemailer';
    this.fromEmail = process.env.EMAIL_FROM || 'noreply@bizpickr.com';
    this.fromName = process.env.EMAIL_FROM_NAME || 'BizPickr';
  }

  /**
   * Send email
   * @param {Object} emailData - Email data
   * @returns {Promise<boolean>} Send success
   */
  async sendEmail(emailData) {
    try {
      const { to, subject, template, data } = emailData;

      // Validate email data
      if (!to || !subject) {
        throw new Error('Email recipient and subject are required');
      }

      // Get email content from template
      const { html, text } = await this.getEmailContent(template, data);

      // Send email based on provider
      switch (this.provider) {
        case 'nodemailer':
          return await this.sendViaNodemailer({ to, subject, html, text });
        case 'sendgrid':
          return await this.sendViaSendGrid({ to, subject, html, text });
        case 'aws-ses':
          return await this.sendViaAWSSES({ to, subject, html, text });
        default:
          // For development, just log the email
          safeLogger.info('Email would be sent (development mode)', {
            to,
            subject,
            template,
            provider: this.provider,
          });
          return true;
      }
    } catch (error) {
      safeLogger.error('Failed to send email', {
        error: error.message,
        emailData: {
          to: emailData.to,
          subject: emailData.subject,
          template: emailData.template,
        },
      });
      throw error;
    }
  }

  /**
   * Get email content from template
   * @param {string} template - Template name
   * @param {Object} data - Template data
   * @returns {Promise<Object>} Email content
   */
  async getEmailContent(template, data = {}) {
    try {
      switch (template) {
        case 'email-verification':
          return this.getEmailVerificationTemplate(data);
        case 'password-reset':
          return this.getPasswordResetTemplate(data);
        case 'welcome':
          return this.getWelcomeTemplate(data);
        default:
          throw new Error(`Unknown email template: ${template}`);
      }
    } catch (error) {
      safeLogger.error('Failed to get email content', {
        error: error.message,
        template,
      });
      throw error;
    }
  }

  /**
   * Email verification template
   * @param {Object} data - Template data
   * @returns {Object} Email content
   */
  getEmailVerificationTemplate(data) {
    const { verificationUrl, token, expiresIn, supportEmail } = data;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Verify Your Email - BizPickr</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #007bff; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
          .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Verify Your Email Address</h1>
          </div>
          <div class="content">
            <p>Hello!</p>
            <p>Thank you for signing up with BizPickr. Please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </p>
            <p>This verification link will expire in ${expiresIn}.</p>
            <p>If you didn't create an account with BizPickr, you can safely ignore this email.</p>
            <p>If you're having trouble clicking the button, copy and paste this URL into your browser:</p>
            <p style="word-break: break-all; color: #007bff;">${verificationUrl}</p>
          </div>
          <div class="footer">
            <p>If you have any questions, please contact us at <a href="mailto:${supportEmail}">${supportEmail}</a></p>
            <p>&copy; 2024 BizPickr. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Verify Your Email Address - BizPickr

      Hello!

      Thank you for signing up with BizPickr. Please verify your email address by visiting the link below:

      ${verificationUrl}

      This verification link will expire in ${expiresIn}.

      If you didn't create an account with BizPickr, you can safely ignore this email.

      If you have any questions, please contact us at ${supportEmail}

      © 2024 BizPickr. All rights reserved.
    `;

    return { html, text };
  }

  /**
   * Password reset template
   * @param {Object} data - Template data
   * @returns {Object} Email content
   */
  getPasswordResetTemplate(data) {
    const { resetUrl, expiresIn, supportEmail } = data;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Reset Your Password - BizPickr</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; }
          .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reset Your Password</h1>
          </div>
          <div class="content">
            <p>Hello!</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </p>
            <p>This link will expire in ${expiresIn}.</p>
            <p>If you didn't request a password reset, you can safely ignore this email.</p>
            <p>If you're having trouble clicking the button, copy and paste this URL into your browser:</p>
            <p style="word-break: break-all; color: #dc3545;">${resetUrl}</p>
          </div>
          <div class="footer">
            <p>If you have any questions, please contact us at <a href="mailto:${supportEmail}">${supportEmail}</a></p>
            <p>&copy; 2024 BizPickr. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Reset Your Password - BizPickr

      Hello!

      We received a request to reset your password. Visit the link below to create a new password:

      ${resetUrl}

      This link will expire in ${expiresIn}.

      If you didn't request a password reset, you can safely ignore this email.

      If you have any questions, please contact us at ${supportEmail}

      © 2024 BizPickr. All rights reserved.
    `;

    return { html, text };
  }

  /**
   * Welcome template
   * @param {Object} data - Template data
   * @returns {Object} Email content
   */
  getWelcomeTemplate(data) {
    const { fullName, supportEmail } = data;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Welcome to BizPickr</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to BizPickr!</h1>
          </div>
          <div class="content">
            <p>Hello ${fullName || 'there'}!</p>
            <p>Welcome to BizPickr! Your account has been successfully created and verified.</p>
            <p>We're excited to have you on board. Here's what you can do next:</p>
            <ul>
              <li>Complete your profile</li>
              <li>Explore our features</li>
              <li>Connect with other users</li>
              <li>Start building your business network</li>
            </ul>
            <p>If you have any questions or need help getting started, don't hesitate to reach out to our support team.</p>
          </div>
          <div class="footer">
            <p>If you have any questions, please contact us at <a href="mailto:${supportEmail}">${supportEmail}</a></p>
            <p>&copy; 2024 BizPickr. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Welcome to BizPickr!

      Hello ${fullName || 'there'}!

      Welcome to BizPickr! Your account has been successfully created and verified.

      We're excited to have you on board. Here's what you can do next:
      - Complete your profile
      - Explore our features
      - Connect with other users
      - Start building your business network

      If you have any questions or need help getting started, don't hesitate to reach out to our support team.

      If you have any questions, please contact us at ${supportEmail}

      © 2024 BizPickr. All rights reserved.
    `;

    return { html, text };
  }

  /**
   * Send email via Nodemailer
   * @param {Object} emailData - Email data
   * @returns {Promise<boolean>} Send success
   */
  async sendViaNodemailer(emailData) {
    // Implementation will be added when Nodemailer is configured
    safeLogger.info('Nodemailer integration not configured', emailData);
    return true;
  }

  /**
   * Send email via SendGrid
   * @param {Object} emailData - Email data
   * @returns {Promise<boolean>} Send success
   */
  async sendViaSendGrid(emailData) {
    // Implementation will be added when SendGrid is configured
    safeLogger.info('SendGrid integration not configured', emailData);
    return true;
  }

  /**
   * Send email via AWS SES
   * @param {Object} emailData - Email data
   * @returns {Promise<boolean>} Send success
   */
  async sendViaAWSSES(emailData) {
    // Implementation will be added when AWS SES is configured
    safeLogger.info('AWS SES integration not configured', emailData);
    return true;
  }
}

export default new EmailService();
