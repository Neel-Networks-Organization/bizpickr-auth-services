import mongoose from 'mongoose';

const userActivitySchema = new mongoose.Schema(
  {
    userId: {
      type: String, // Changed from ObjectId to String for MySQL UUID compatibility
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
    sessionId: {
      type: String,
      description: 'Associated session ID',
      index: true,
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
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
      description: 'Risk score (0-100)',
    },
  },
  {
    timestamps: true,
  },
);

// userActivitySchema.index({ userId: 1, action: 1, createdAt: -1 });
// userActivitySchema.index({ severity: 1 });
// userActivitySchema.index({ category: 1 });
// userActivitySchema.index({ status: 1 });
// userActivitySchema.index({ sessionId: 1 });
// userActivitySchema.index({ ipAddress: 1 });

// Static method to log activity
userActivitySchema.statics.logActivity = async function(activityData) {
  // Calculate risk score before saving
  activityData.riskScore = calculateRiskScore(activityData);
  return this.create(activityData);
};

// Instance method to update risk score
userActivitySchema.methods.updateRiskScore = async function() {
  this.riskScore = calculateRiskScore(this);
  return this.save();
};

// Helper function for risk score calculation
function calculateRiskScore(activity) {
  let score = 0;
  switch (activity.severity) {
  case 'critical':
    score += 40;
    break;
  case 'high':
    score += 25;
    break;
  case 'medium':
    score += 15;
    break;
  case 'low':
    score += 5;
    break;
  }
  switch (activity.category) {
  case 'security':
    score += 20;
    break;
  case 'authentication':
    score += 15;
    break;
  case 'authorization':
    score += 10;
    break;
  case 'data_access':
    score += 8;
    break;
  case 'system':
    score += 5;
    break;
  }
  if (activity.status === 'failure') score += 10;
  const highRiskActions = [
    'login_failed',
    'password_reset',
    'account_lock',
    'suspicious_activity',
  ];
  if (highRiskActions.includes(activity.action)) score += 15;
  return Math.min(score, 100);
}

const UserActivity = mongoose.model('UserActivity', userActivitySchema);
export default UserActivity;
