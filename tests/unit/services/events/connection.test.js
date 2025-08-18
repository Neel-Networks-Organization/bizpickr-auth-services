import { jest } from "@jest/globals";
import amqplib from "amqplib";
import rabbitMQConnection from "../../../../src/events/connection.js";
import { rabbitMQConfig } from "../../../../src/config/rabbitMQ.js";
import { safeLogger } from "../../../../src/config/logger.js";

// Mock dependencies
jest.mock("amqplib");
jest.mock("../../../../src/config/rabbitMQ.js");
jest.mock("../../../../src/config/logger.js", () => ({
  safeLogger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

describe("RabbitMQ Connection", () => {
  let mockConnection;
  let mockChannel;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock RabbitMQ config
    rabbitMQConfig.url = "amqp://localhost:5672";
    rabbitMQConfig.connectionOptions = { heartbeat: 60 };
    rabbitMQConfig.retryMechanism = {
      maxRetries: 3,
      initialInterval: 1000,
      multiplier: 2,
    };
    rabbitMQConfig.deadLetterExchange = {
      name: "dlx",
      type: "direct",
      queue: "dlq",
      routingKey: "dead.letter",
    };
    rabbitMQConfig.exchanges = {
      auth: {
        name: "auth.exchange",
        type: "topic",
        options: { durable: true },
      },
      user: {
        name: "user.exchange",
        type: "topic",
        options: { durable: true },
      },
    };
    rabbitMQConfig.queues = {
      userVerified: {
        name: "user.verified.queue",
        options: { durable: true },
        bindings: [{ exchange: "auth.exchange", routingKey: "user.verified" }],
      },
    };
    rabbitMQConfig.consumerOptions = {
      prefetch: 10,
      noAck: false,
    };

    // Mock AMQP connection
    mockConnection = {
      createChannel: jest.fn(),
      close: jest.fn(),
      on: jest.fn(),
    };

    // Mock AMQP channel
    mockChannel = {
      assertExchange: jest.fn(),
      assertQueue: jest.fn(),
      bindQueue: jest.fn(),
      publish: jest.fn(),
      consume: jest.fn(),
      ack: jest.fn(),
      nack: jest.fn(),
      prefetch: jest.fn(),
      close: jest.fn(),
      cancel: jest.fn(),
      checkQueue: jest.fn(),
      on: jest.fn(),
    };

    amqplib.connect.mockResolvedValue(mockConnection);
    mockConnection.createChannel.mockResolvedValue(mockChannel);
  });

  describe("Initialization", () => {
    it("should initialize RabbitMQ connection successfully", async () => {
      await rabbitMQConnection.init();

      expect(amqplib.connect).toHaveBeenCalledWith(
        rabbitMQConfig.url,
        rabbitMQConfig.connectionOptions
      );
      expect(safeLogger.info).toHaveBeenCalledWith(
        "Successfully connected to RabbitMQ"
      );
    });

    it("should handle connection errors gracefully", async () => {
      const connectionError = new Error("Connection refused");
      amqplib.connect.mockRejectedValue(connectionError);

      await rabbitMQConnection.init();

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Failed to connect to RabbitMQ",
        {
          message: connectionError.message,
          stack: connectionError.stack,
        }
      );
    });

    it("should setup event listeners on connection", async () => {
      await rabbitMQConnection.init();

      expect(mockConnection.on).toHaveBeenCalledWith(
        "error",
        expect.any(Function)
      );
      expect(mockConnection.on).toHaveBeenCalledWith(
        "close",
        expect.any(Function)
      );
    });

    it("should setup dead letter exchange", async () => {
      await rabbitMQConnection.init();

      expect(mockChannel.assertExchange).toHaveBeenCalledWith("dlx", "direct", {
        durable: true,
        autoDelete: false,
      });
      expect(mockChannel.assertQueue).toHaveBeenCalledWith(
        "dlq",
        expect.objectContaining({
          durable: true,
          arguments: expect.objectContaining({
            "x-message-ttl": 7 * 24 * 60 * 60 * 1000,
          }),
        })
      );
    });

    it("should setup default exchanges", async () => {
      await rabbitMQConnection.init();

      expect(mockChannel.assertExchange).toHaveBeenCalledWith(
        "auth.exchange",
        "topic",
        { durable: true, autoDelete: false }
      );
      expect(mockChannel.assertExchange).toHaveBeenCalledWith(
        "user.exchange",
        "topic",
        { durable: true, autoDelete: false }
      );
    });

    it("should setup default queues", async () => {
      await rabbitMQConnection.init();

      expect(mockChannel.assertQueue).toHaveBeenCalledWith(
        "user.verified.queue",
        expect.objectContaining({
          durable: true,
          deadLetterExchange: "dlx",
          messageTtl: 86400000,
        })
      );
      expect(mockChannel.bindQueue).toHaveBeenCalledWith(
        "user.verified.queue",
        "auth.exchange",
        "user.verified"
      );
    });
  });

  describe("Channel Management", () => {
    beforeEach(async () => {
      await rabbitMQConnection.init();
    });

    it("should create channel with correct name", async () => {
      const channel = await rabbitMQConnection.createChannel("test-channel");

      expect(mockConnection.createChannel).toHaveBeenCalled();
      expect(channel).toBe(mockChannel);
    });

    it("should reuse existing valid channel", async () => {
      const channel1 = await rabbitMQConnection.createChannel("test-channel");
      const channel2 = await rabbitMQConnection.createChannel("test-channel");

      expect(mockConnection.createChannel).toHaveBeenCalledTimes(1);
      expect(channel1).toBe(channel2);
    });

    it("should recreate invalid channel", async () => {
      // First call succeeds
      await rabbitMQConnection.createChannel("test-channel");

      // Second call fails with invalid channel
      mockChannel.checkQueue.mockRejectedValue(new Error("Channel closed"));

      await rabbitMQConnection.createChannel("test-channel");

      expect(mockConnection.createChannel).toHaveBeenCalledTimes(2);
    });

    it("should handle channel creation errors", async () => {
      mockConnection.createChannel.mockRejectedValue(
        new Error("Channel creation failed")
      );

      await expect(
        rabbitMQConnection.createChannel("test-channel")
      ).rejects.toThrow("Channel creation failed");
    });

    it("should setup channel event listeners", async () => {
      await rabbitMQConnection.createChannel("test-channel");

      expect(mockChannel.on).toHaveBeenCalledWith(
        "error",
        expect.any(Function)
      );
      expect(mockChannel.on).toHaveBeenCalledWith(
        "close",
        expect.any(Function)
      );
    });

    it("should close channel successfully", async () => {
      await rabbitMQConnection.createChannel("test-channel");
      await rabbitMQConnection.closeChannel("test-channel");

      expect(mockChannel.close).toHaveBeenCalled();
    });

    it("should handle channel close errors gracefully", async () => {
      await rabbitMQConnection.createChannel("test-channel");
      mockChannel.close.mockRejectedValue(new Error("Close failed"));

      await rabbitMQConnection.closeChannel("test-channel");

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Error closing channel 'test-channel': Close failed"
      );
    });
  });

  describe("Exchange Management", () => {
    beforeEach(async () => {
      await rabbitMQConnection.init();
    });

    it("should create exchange with default options", async () => {
      await rabbitMQConnection.createExchange(
        "test-channel",
        "test.exchange",
        "topic"
      );

      expect(mockChannel.assertExchange).toHaveBeenCalledWith(
        "test.exchange",
        "topic",
        { durable: true, autoDelete: false }
      );
    });

    it("should create exchange with custom options", async () => {
      const customOptions = { durable: false, autoDelete: true };
      await rabbitMQConnection.createExchange(
        "test-channel",
        "test.exchange",
        "fanout",
        customOptions
      );

      expect(mockChannel.assertExchange).toHaveBeenCalledWith(
        "test.exchange",
        "fanout",
        { durable: false, autoDelete: true }
      );
    });

    it("should handle exchange creation errors", async () => {
      mockChannel.assertExchange.mockRejectedValue(
        new Error("Exchange creation failed")
      );

      await expect(
        rabbitMQConnection.createExchange(
          "test-channel",
          "test.exchange",
          "topic"
        )
      ).rejects.toThrow("Exchange creation failed");
    });
  });

  describe("Queue Management", () => {
    beforeEach(async () => {
      await rabbitMQConnection.init();
    });

    it("should create queue with default options", async () => {
      const result = await rabbitMQConnection.createQueue(
        "test-channel",
        "test.queue"
      );

      expect(mockChannel.assertQueue).toHaveBeenCalledWith(
        "test.queue",
        expect.objectContaining({
          durable: true,
          deadLetterExchange: "dlx",
          messageTtl: 86400000,
        })
      );
      expect(result).toBeDefined();
    });

    it("should create queue with custom options", async () => {
      const customOptions = { durable: false, messageTtl: 3600000 };
      await rabbitMQConnection.createQueue(
        "test-channel",
        "test.queue",
        customOptions
      );

      expect(mockChannel.assertQueue).toHaveBeenCalledWith(
        "test.queue",
        expect.objectContaining({
          durable: false,
          deadLetterExchange: "dlx",
          messageTtl: 3600000,
        })
      );
    });

    it("should bind queue to exchange", async () => {
      await rabbitMQConnection.bindQueue(
        "test-channel",
        "test.queue",
        "test.exchange",
        "test.routing.key"
      );

      expect(mockChannel.bindQueue).toHaveBeenCalledWith(
        "test.queue",
        "test.exchange",
        "test.routing.key"
      );
    });

    it("should handle queue creation errors", async () => {
      mockChannel.assertQueue.mockRejectedValue(
        new Error("Queue creation failed")
      );

      await expect(
        rabbitMQConnection.createQueue("test-channel", "test.queue")
      ).rejects.toThrow("Queue creation failed");
    });
  });

  describe("Message Publishing", () => {
    beforeEach(async () => {
      await rabbitMQConnection.init();
    });

    it("should publish message successfully", async () => {
      const message = { userId: "123", action: "login" };
      const result = await rabbitMQConnection.publish(
        "test-channel",
        "test.exchange",
        "test.routing.key",
        message
      );

      expect(mockChannel.publish).toHaveBeenCalledWith(
        "test.exchange",
        "test.routing.key",
        expect.any(Buffer),
        expect.objectContaining({
          persistent: true,
          contentType: "application/json",
          contentEncoding: "utf-8",
          timestamp: expect.any(Number),
        })
      );
      expect(result).toBe(true);
    });

    it("should publish message with custom options", async () => {
      const message = { userId: "123", action: "login" };
      const options = { persistent: false, priority: 5 };

      await rabbitMQConnection.publish(
        "test-channel",
        "test.exchange",
        "test.routing.key",
        message,
        options
      );

      expect(mockChannel.publish).toHaveBeenCalledWith(
        "test.exchange",
        "test.routing.key",
        expect.any(Buffer),
        expect.objectContaining({
          persistent: false,
          priority: 5,
          contentType: "application/json",
        })
      );
    });

    it("should handle buffer messages", async () => {
      const message = Buffer.from("test message");

      await rabbitMQConnection.publish(
        "test-channel",
        "test.exchange",
        "test.routing.key",
        message
      );

      expect(mockChannel.publish).toHaveBeenCalledWith(
        "test.exchange",
        "test.routing.key",
        message,
        expect.any(Object)
      );
    });

    it("should handle publish failures", async () => {
      mockChannel.publish.mockReturnValue(false);

      const result = await rabbitMQConnection.publish(
        "test-channel",
        "test.exchange",
        "test.routing.key",
        { test: "message" }
      );

      expect(result).toBe(false);
      expect(safeLogger.warn).toHaveBeenCalledWith(
        "Failed to publish message to exchange 'test.exchange' with routing key 'test.routing.key'"
      );
    });
  });

  describe("Message Consumption", () => {
    beforeEach(async () => {
      await rabbitMQConnection.init();
    });

    it("should start consumer successfully", async () => {
      const callback = jest.fn();
      const message = {
        content: Buffer.from(JSON.stringify({ test: "data" })),
      };

      mockChannel.consume.mockResolvedValue({ consumerTag: "test-consumer" });

      const consumerTag = await rabbitMQConnection.consume(
        "test-channel",
        "test.queue",
        callback
      );

      expect(mockChannel.prefetch).toHaveBeenCalledWith(10);
      expect(mockChannel.consume).toHaveBeenCalledWith(
        "test.queue",
        expect.any(Function),
        {
          noAck: false,
        }
      );
      expect(consumerTag).toBe("test-consumer");
    });

    it("should handle message processing successfully", async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      const message = {
        content: Buffer.from(JSON.stringify({ test: "data" })),
      };

      mockChannel.consume.mockImplementation((queue, msgCallback) => {
        msgCallback(message);
        return Promise.resolve({ consumerTag: "test-consumer" });
      });

      await rabbitMQConnection.consume("test-channel", "test.queue", callback);

      expect(callback).toHaveBeenCalledWith(
        { test: "data" },
        message,
        mockChannel
      );
      expect(mockChannel.ack).toHaveBeenCalledWith(message);
    });

    it("should handle message processing errors", async () => {
      const callback = jest
        .fn()
        .mockRejectedValue(new Error("Processing failed"));
      const message = {
        content: Buffer.from(JSON.stringify({ test: "data" })),
      };

      mockChannel.consume.mockImplementation((queue, msgCallback) => {
        msgCallback(message);
        return Promise.resolve({ consumerTag: "test-consumer" });
      });

      await rabbitMQConnection.consume("test-channel", "test.queue", callback);

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Error processing message from queue 'test.queue': Processing failed"
      );
      expect(mockChannel.nack).toHaveBeenCalledWith(message, false, false);
    });

    it("should handle null messages (consumer cancellation)", async () => {
      const callback = jest.fn();

      mockChannel.consume.mockImplementation((queue, msgCallback) => {
        msgCallback(null);
        return Promise.resolve({ consumerTag: "test-consumer" });
      });

      await rabbitMQConnection.consume("test-channel", "test.queue", callback);

      expect(safeLogger.warn).toHaveBeenCalledWith(
        "Consumer was cancelled by RabbitMQ: test.queue"
      );
    });

    it("should handle consumer cancellation", async () => {
      await rabbitMQConnection.cancelConsumer("test-channel", "test-consumer");

      expect(mockChannel.cancel).toHaveBeenCalledWith("test-consumer");
    });

    it("should handle consumer cancellation errors", async () => {
      mockChannel.cancel.mockRejectedValue(new Error("Cancel failed"));

      await rabbitMQConnection.cancelConsumer("test-channel", "test-consumer");

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Error cancelling consumer 'test-consumer': Cancel failed"
      );
    });
  });

  describe("Reconnection Logic", () => {
    it("should attempt reconnection on connection error", async () => {
      await rabbitMQConnection.init();

      // Simulate connection error
      const errorCallback = mockConnection.on.mock.calls.find(
        (call) => call[0] === "error"
      )[1];
      errorCallback(new Error("Connection lost"));

      // Wait for reconnection attempt
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(safeLogger.error).toHaveBeenCalledWith(
        "RabbitMQ connection error",
        {
          message: "Connection lost",
          stack: expect.any(String),
        }
      );
    });

    it("should attempt reconnection on connection close", async () => {
      await rabbitMQConnection.init();

      // Simulate connection close
      const closeCallback = mockConnection.on.mock.calls.find(
        (call) => call[0] === "close"
      )[1];
      closeCallback();

      // Wait for reconnection attempt
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(safeLogger.warn).toHaveBeenCalledWith(
        "RabbitMQ connection closed"
      );
    });

    it("should respect max retry attempts", async () => {
      amqplib.connect.mockRejectedValue(new Error("Connection failed"));

      await rabbitMQConnection.init();

      // Wait for all retry attempts
      await new Promise((resolve) => setTimeout(resolve, 1000));

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Failed to reconnect to RabbitMQ after 3 attempts"
      );
    });
  });

  describe("Cleanup", () => {
    it("should close all channels and connection", async () => {
      await rabbitMQConnection.init();
      await rabbitMQConnection.createChannel("test-channel");

      await rabbitMQConnection.close();

      expect(mockChannel.close).toHaveBeenCalled();
      expect(mockConnection.close).toHaveBeenCalled();
      expect(safeLogger.info).toHaveBeenCalledWith(
        "Channel 'test-channel' closed"
      );
      expect(safeLogger.info).toHaveBeenCalledWith(
        "RabbitMQ connection closed"
      );
    });

    it("should handle cleanup errors gracefully", async () => {
      await rabbitMQConnection.init();
      await rabbitMQConnection.createChannel("test-channel");

      mockChannel.close.mockRejectedValue(new Error("Channel close failed"));
      mockConnection.close.mockRejectedValue(
        new Error("Connection close failed")
      );

      await rabbitMQConnection.close();

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Error closing channel 'test-channel': Channel close failed"
      );
      expect(safeLogger.error).toHaveBeenCalledWith(
        "Error closing RabbitMQ connection: Connection close failed"
      );
    });
  });

  describe("Error Handling", () => {
    it("should handle JSON parsing errors in message consumption", async () => {
      const callback = jest.fn();
      const invalidMessage = { content: Buffer.from("invalid json") };

      mockChannel.consume.mockImplementation((queue, msgCallback) => {
        msgCallback(invalidMessage);
        return Promise.resolve({ consumerTag: "test-consumer" });
      });

      await rabbitMQConnection.consume("test-channel", "test.queue", callback);

      expect(safeLogger.error).toHaveBeenCalledWith(
        "Error processing message from queue 'test.queue':",
        expect.any(Error)
      );
    });

    it("should handle missing channel errors", async () => {
      await rabbitMQConnection.cancelConsumer(
        "non-existent-channel",
        "test-consumer"
      );

      expect(safeLogger.warn).toHaveBeenCalledWith(
        "Channel 'non-existent-channel' not found for cancelling consumer 'test-consumer'"
      );
    });
  });
});
