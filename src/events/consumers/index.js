/**
 * Events Consumers Index
 * Central export for all event consumers
 */

// Email events consumer
export {
  startEmailEventsConsumer,
  stopEmailEventsConsumer,
  isEmailEventsConsumerRunning,
  getEmailEventsConsumerStatus,
} from './emailEvents.consumer.js';

// Notification events consumer
export {
  startNotificationEventsConsumer,
  stopNotificationEventsConsumer,
  isNotificationEventsConsumerRunning,
  getNotificationEventsConsumerStatus,
} from './notificationEvents.consumer.js';

// User events consumer
export {
  startUserEventsConsumer,
  stopUserEventsConsumer,
  isUserEventsConsumerRunning,
  getUserEventsConsumerStatus,
} from './userEvents.consumer.js';

// Consumer management
export const consumerTypes = {
  EMAIL: 'email',
  NOTIFICATION: 'notification',
  USER: 'user',
};
