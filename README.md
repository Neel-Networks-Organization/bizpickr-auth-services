# AuthService - Simple & Focused

A clean, simple authentication microservice for BizPickr. Built for **2 developers** - no over-engineering!

## 🚀 Quick Start

```bash
# Setup development environment
npm run setup:dev

# Start development server
npm run dev

# Run tests
npm test

# Start production server
npm start
```

## 📋 What This Service Does

- **User Authentication**: Login, logout, session management
- **JWT Tokens**: Secure token generation and validation
- **Security**: Basic security with Helmet, CORS, rate limiting
- **Database**: MongoDB + MySQL + Redis
- **gRPC**: Service-to-service communication
- **Events**: RabbitMQ for async operations

## 🛠️ Development

### Prerequisites
- Node.js 18+
- MySQL
- Redis
- RabbitMQ
- MongoDB

### Environment Setup
```bash
# Copy environment file
cp env.example .env

# Update database credentials in .env
# Run setup script
npm run setup:dev
```

### Available Commands
```bash
npm run dev          # Start development server
npm run test         # Run unit tests
npm run test:watch   # Run tests in watch mode
npm run lint         # Check code quality
npm run lint:fix     # Fix linting issues
npm run format       # Format code with Prettier
```

## 🏗️ Architecture

```
src/
├── controllers/     # Request handlers
├── services/        # Business logic
├── models/          # Database models
├── middlewares/     # Express middlewares
├── routes/          # API routes
├── config/          # Configuration
├── utils/           # Utility functions
└── grpc/            # gRPC services
```

## 🔒 Security Features

- Helmet for security headers
- CORS protection
- Rate limiting
- Input validation
- JWT token security

## 📊 Testing

Simple testing with Jest:
- Unit tests for services
- Integration tests for APIs
- Basic coverage reporting

## 🐳 Docker

```bash
# Build image
npm run docker:build

# Run container
npm run docker:run

# Use docker-compose
npm run docker:compose
```

## 🌟 Why Simple?

- **2 developers** = Keep it focused
- **MVP first** = Add complexity later
- **Easy maintenance** = Less overhead
- **Fast development** = Quick iterations

## 📝 License

ISC License - Neel Networks
