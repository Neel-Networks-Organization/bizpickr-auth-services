import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: String, // Changed from ObjectId to String for MySQL UUID compatibility
      description: 'User who performed the action (MySQL UUID string)',
    },
    action: {
      type: String,
      required: true,
      maxlength: 100,
      description: 'Action performed (e.g., USER_LOGIN, PASSWORD_CHANGE)',
    },
    resourceType: {
      type: String,
      maxlength: 50,
      description: 'Type of resource affected (e.g., USER, SESSION)',
    },
    resourceId: {
      type: String,
      maxlength: 100,
      description: 'ID of the affected resource',
    },
    details: {
      type: Object,
      description: 'Additional details about the action',
    },
    ipAddress: {
      type: String,
      maxlength: 45,
      description: 'IP address of the request',
    },
    userAgent: {
      type: String,
      description: 'User agent string',
    },
    status: {
      type: String,
      enum: ['success', 'failed', 'pending'],
      default: 'success',
      description: 'Status of the action',
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'low',
      description: 'Severity level of the action',
    },
    metadata: {
      type: Object,
      description: 'Additional metadata',
    },
  },
  {
    timestamps: true,
  }
);

auditLogSchema.index({ userId: 1, action: 1, createdAt: -1 });
auditLogSchema.index({ status: 1 });
auditLogSchema.index({ severity: 1 });
auditLogSchema.index({ ipAddress: 1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);
export default AuditLog;
