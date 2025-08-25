import mongoose from 'mongoose';

const userActivitySchema = new mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
      index: true,
      description: 'Associated user ID (MySQL UUID string)',
    },
    action: {
      type: String,
      required: true,
      maxlength: 100,
      description: 'Activity action type',
      index: true,
    },
    description: {
      type: String,
      default: 'No description',
      description: 'Activity description',
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'low',
      description: 'Activity severity level',
      index: true,
    },
    category: {
      type: String,
      enum: [
        'authentication',
        'authorization',
        'data_access',
        'system',
        'security',
      ],
      default: 'system',
      description: 'Activity category',
      index: true,
    },
    ipAddress: {
      type: String,
      maxlength: 45,
      description: 'IP address of activity',
      index: true,
    },
    userAgent: {
      type: String,
      description: 'User agent string',
    },
    deviceInfo: {
      type: Object,
      description: 'Device information',
    },
    locationInfo: {
      type: Object,
      description: 'Geographic location information',
    },
    requestId: {
      type: String,
      maxlength: 255,
      description: 'Request correlation ID',
    },
    status: {
      type: String,
      enum: ['success', 'failure', 'pending'],
      default: 'success',
      description: 'Activity status',
      index: true,
    },
    metadata: {
      type: Object,
      default: {},
      description: 'Additional activity metadata',
    },
  },
  {
    timestamps: true,
  }
);

userActivitySchema.index({ userId: 1, action: 1, createdAt: -1 });
userActivitySchema.index({ severity: 1 });
userActivitySchema.index({ category: 1 });
userActivitySchema.index({ status: 1 });
userActivitySchema.index({ requestId: 1 });
userActivitySchema.index({ ipAddress: 1 });

const UserActivity = mongoose.model('UserActivity', userActivitySchema);
export default UserActivity;
