# 🚀 AuthService Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the AuthService microservice in various environments, from development to production.

## 📋 Prerequisites

### System Requirements

- **Node.js**: 18.x or higher
- **Docker**: 20.x or higher
- **Docker Compose**: 2.x or higher
- **Kubernetes**: 1.24+ (for K8s deployment)
- **Database**: MySQL 8.0+, MongoDB 6.0+
- **Cache**: Redis 6.0+
- **Message Queue**: RabbitMQ 3.8+

### Infrastructure Requirements

#### **Development Environment**

- **CPU**: 2 cores minimum
- **RAM**: 4GB minimum
- **Storage**: 20GB available space
- **Network**: Local network access

#### **Staging Environment**

- **CPU**: 4 cores minimum
- **RAM**: 8GB minimum
- **Storage**: 50GB available space
- **Network**: Internal network access

#### **Production Environment**

- **CPU**: 8 cores minimum
- **RAM**: 16GB minimum
- **Storage**: 100GB available space
- **Network**: High-speed internet access
- **Load Balancer**: Required for high availability

## 🏗️ Deployment Strategies

### 1. **Docker Deployment** (Recommended for most cases)

#### **Single Container Deployment**

```bash
# Build the Docker image
docker build -t auth-service:latest .

# Run the container
docker run -d \
  --name auth-service \
  -p 3001:3001 \
  -e NODE_ENV=production \
  -e DB_HOST=your-mysql-host \
  -e DB_NAME=auth_service \
  -e DB_USER=your-db-user \
  -e DB_PASSWORD=your-db-password \
  -e REDIS_HOST=your-redis-host \
  -e REDIS_PORT=6379 \
  -e JWT_SECRET=your-jwt-secret \
  -e REFRESH_TOKEN_SECRET=your-refresh-secret \
  auth-service:latest
```

#### **Docker Compose Deployment**

```yaml
# docker-compose.yml
version: "3.8"

services:
  auth-service:
    build: .
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - DB_HOST=mysql
      - DB_NAME=auth_service
      - DB_USER=auth_user
      - DB_PASSWORD=auth_password
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - JWT_SECRET=${JWT_SECRET}
      - REFRESH_TOKEN_SECRET=${REFRESH_TOKEN_SECRET}
    depends_on:
      - mysql
      - mongodb
      - redis
      - rabbitmq
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: root_password
      MYSQL_DATABASE: auth_service
      MYSQL_USER: auth_user
      MYSQL_PASSWORD: auth_password
    volumes:
      - mysql_data:/var/lib/mysql
    ports:
      - "3306:3306"

  mongodb:
    image: mongo:6.0
    environment:
      MONGO_INITDB_DATABASE: auth_service
    volumes:
      - mongodb_data:/data/db
    ports:
      - "27017:27017"

  redis:
    image: redis:6.0-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  rabbitmq:
    image: rabbitmq:3.8-management
    environment:
      RABBITMQ_DEFAULT_USER: admin
      RABBITMQ_DEFAULT_PASS: admin_password
    ports:
      - "5672:5672"
      - "15672:15672"
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq

volumes:
  mysql_data:
  mongodb_data:
  redis_data:
  rabbitmq_data:
```

**Deploy with Docker Compose:**

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down
```

### 2. **Kubernetes Deployment**

#### **Kubernetes Manifests**

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-service
```

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: auth-service
data:
  NODE_ENV: "production"
  DB_HOST: "mysql-service"
  DB_NAME: "auth_service"
  REDIS_HOST: "redis-service"
  RABBITMQ_HOST: "rabbitmq-service"
```

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-service-secrets
  namespace: auth-service
type: Opaque
data:
  JWT_SECRET: <base64-encoded-jwt-secret>
  REFRESH_TOKEN_SECRET: <base64-encoded-refresh-secret>
  DB_PASSWORD: <base64-encoded-db-password>
  GOOGLE_CLIENT_SECRET: <base64-encoded-google-secret>
```

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
        - name: auth-service
          image: auth-service:latest
          ports:
            - containerPort: 3001
          envFrom:
            - configMapRef:
                name: auth-service-config
            - secretRef:
                name: auth-service-secrets
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: 3001
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 3001
            initialDelaySeconds: 5
            periodSeconds: 5
```

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: auth-service
spec:
  selector:
    app: auth-service
  ports:
    - port: 80
      targetPort: 3001
  type: ClusterIP
```

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  namespace: auth-service
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - auth.yourdomain.com
      secretName: auth-service-tls
  rules:
    - host: auth.yourdomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: auth-service
                port:
                  number: 80
```

**Deploy to Kubernetes:**

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Apply configurations
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check deployment status
kubectl get pods -n auth-service
kubectl get services -n auth-service
kubectl get ingress -n auth-service
```

### 3. **Cloud Platform Deployment**

#### **AWS ECS Deployment**

```json
// task-definition.json
{
  "family": "auth-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/auth-service-task-role",
  "containerDefinitions": [
    {
      "name": "auth-service",
      "image": "your-account.dkr.ecr.region.amazonaws.com/auth-service:latest",
      "portMappings": [
        {
          "containerPort": 3001,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:3001/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

#### **Google Cloud Run Deployment**

```bash
# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/PROJECT_ID/auth-service

# Deploy to Cloud Run
gcloud run deploy auth-service \
  --image gcr.io/PROJECT_ID/auth-service \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars NODE_ENV=production \
  --set-env-vars DB_HOST=your-db-host \
  --memory 1Gi \
  --cpu 1 \
  --max-instances 10
```

## 🔧 Environment Configuration

### Environment Variables

#### **Required Environment Variables**

```bash
# Core Configuration
NODE_ENV=production
PORT=3001

# Database Configuration
DB_HOST=your-mysql-host
DB_PORT=3306
DB_NAME=auth_service
DB_USER=your-db-user
DB_PASSWORD=your-db-password

# Redis Configuration
REDIS_HOST=your-redis-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key
JWT_EXPIRY=15m
REFRESH_TOKEN_SECRET=your-super-secure-refresh-secret-key
REFRESH_TOKEN_EXPIRY=7d

# OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/api/v1/auth/google/callback

# Email Configuration
EMAIL_FROM=noreply@yourdomain.com
SUPPORT_EMAIL=support@yourdomain.com
FRONTEND_URL=https://yourdomain.com

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

#### **Optional Environment Variables**

```bash
# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
ENABLE_HEALTH_CHECK=true

# Logging Configuration
LOG_LEVEL=info
LOG_FILE_PATH=/var/log/auth-service
ENABLE_AUDIT_LOGGING=true

# Performance Configuration
DB_POOL_MAX=20
DB_POOL_MIN=5
REDIS_MAX_RETRIES=3
REDIS_RETRY_DELAY=1000

# Feature Flags
ENABLE_EMAIL_VERIFICATION=true
ENABLE_TWO_FACTOR=true
ENABLE_OAUTH=true
ENABLE_DEVICE_FINGERPRINTING=true
```

### Configuration Files

#### **Production Configuration**

```javascript
// config/environments/production.js
export const productionConfig = {
  core: {
    nodeEnv: "production",
    port: process.env.PORT || 3001,
    host: "0.0.0.0",
    corsOrigins: process.env.CORS_ORIGINS?.split(",") || [],
  },
  database: {
    mysql: {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 3306,
      database: process.env.DB_NAME,
      username: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      logging: false,
      pool: {
        max: parseInt(process.env.DB_POOL_MAX) || 20,
        min: parseInt(process.env.DB_POOL_MIN) || 5,
        acquire: 30000,
        idle: 10000,
      },
    },
    mongodb: {
      uri: process.env.MONGODB_URI,
      options: {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      },
    },
  },
  redis: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD,
    maxRetries: parseInt(process.env.REDIS_MAX_RETRIES) || 3,
    retryDelay: parseInt(process.env.REDIS_RETRY_DELAY) || 1000,
  },
  security: {
    jwtSecret: process.env.JWT_SECRET,
    jwtExpiry: process.env.JWT_EXPIRY || "15m",
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
    refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRY || "7d",
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
      max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    },
  },
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI,
    },
  },
  email: {
    from: process.env.EMAIL_FROM,
    supportEmail: process.env.SUPPORT_EMAIL,
    frontendUrl: process.env.FRONTEND_URL,
  },
  features: {
    emailVerification: process.env.ENABLE_EMAIL_VERIFICATION === "true",
    twoFactor: process.env.ENABLE_TWO_FACTOR === "true",
    oauth: process.env.ENABLE_OAUTH === "true",
    deviceFingerprinting: process.env.ENABLE_DEVICE_FINGERPRINTING === "true",
  },
  monitoring: {
    enableMetrics: process.env.ENABLE_METRICS === "true",
    metricsPort: parseInt(process.env.METRICS_PORT) || 9090,
    enableHealthCheck: process.env.ENABLE_HEALTH_CHECK !== "false",
  },
  logging: {
    level: process.env.LOG_LEVEL || "info",
    filePath: process.env.LOG_FILE_PATH,
    enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING === "true",
  },
};
```

## 🔒 Security Configuration

### SSL/TLS Configuration

#### **Nginx Reverse Proxy**

```nginx
# /etc/nginx/sites-available/auth-service
server {
    listen 80;
    server_name auth.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://localhost:3001/health;
        access_log off;
    }
}
```

### Firewall Configuration

```bash
# UFW Firewall Rules
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3001/tcp  # AuthService (if direct access needed)
sudo ufw enable
```

## 📊 Monitoring & Logging

### Health Check Configuration

```bash
# Health check script
#!/bin/bash
HEALTH_URL="http://localhost:3001/health"
MAX_RETRIES=3
RETRY_DELAY=5

for i in $(seq 1 $MAX_RETRIES); do
    response=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)
    if [ $response -eq 200 ]; then
        echo "Health check passed"
        exit 0
    fi
    echo "Health check failed (attempt $i/$MAX_RETRIES)"
    sleep $RETRY_DELAY
done

echo "Health check failed after $MAX_RETRIES attempts"
exit 1
```

### Logging Configuration

```javascript
// Logging configuration for production
const winston = require("winston");
const DailyRotateFile = require("winston-daily-rotate-file");

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "auth-service" },
  transports: [
    new DailyRotateFile({
      filename: "/var/log/auth-service/error-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      level: "error",
      maxSize: "20m",
      maxFiles: "14d",
    }),
    new DailyRotateFile({
      filename: "/var/log/auth-service/combined-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxSize: "20m",
      maxFiles: "14d",
    }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}
```

### Metrics Configuration

```javascript
// Prometheus metrics configuration
const prometheus = require("prom-client");

const collectDefaultMetrics = prometheus.collectDefaultMetrics;
collectDefaultMetrics({ timeout: 5000 });

const httpRequestDurationMicroseconds = new prometheus.Histogram({
  name: "http_request_duration_seconds",
  help: "Duration of HTTP requests in seconds",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.1, 0.5, 1, 2, 5],
});

const httpRequestTotal = new prometheus.Counter({
  name: "http_requests_total",
  help: "Total number of HTTP requests",
  labelNames: ["method", "route", "status_code"],
});

// Metrics endpoint
app.get("/metrics", async (req, res) => {
  res.set("Content-Type", prometheus.register.contentType);
  res.end(await prometheus.register.metrics());
});
```

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Deploy AuthService

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: "18"
          cache: "npm"

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm run test

      - name: Run linting
        run: npm run lint

      - name: Build application
        run: npm run build

  deploy-staging:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1

      - name: Build and push Docker image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: auth-service
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG

      - name: Deploy to ECS
        run: |
          aws ecs update-service --cluster staging --service auth-service --force-new-deployment

  deploy-production:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - uses: actions/checkout@v3

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1

      - name: Build and push Docker image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: auth-service
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG

      - name: Deploy to ECS
        run: |
          aws ecs update-service --cluster production --service auth-service --force-new-deployment
```

## 🚨 Troubleshooting

### Common Deployment Issues

#### **1. Database Connection Issues**

```bash
# Check database connectivity
mysql -h your-db-host -u your-db-user -p your-db-name

# Check database logs
docker logs mysql-container

# Verify environment variables
echo $DB_HOST
echo $DB_USER
echo $DB_PASSWORD
```

#### **2. Redis Connection Issues**

```bash
# Check Redis connectivity
redis-cli -h your-redis-host -p 6379 ping

# Check Redis logs
docker logs redis-container

# Verify Redis configuration
redis-cli -h your-redis-host config get maxmemory
```

#### **3. Port Conflicts**

```bash
# Check what's using port 3001
lsof -i :3001

# Kill conflicting process
kill -9 <PID>

# Check Docker port mapping
docker ps
```

#### **4. Memory Issues**

```bash
# Check memory usage
free -h

# Check Docker memory limits
docker stats

# Increase memory limits
docker run --memory=2g auth-service
```

#### **5. SSL Certificate Issues**

```bash
# Check SSL certificate
openssl s_client -connect auth.yourdomain.com:443

# Renew Let's Encrypt certificate
certbot renew

# Check certificate expiration
certbot certificates
```

### Performance Optimization

#### **1. Database Optimization**

```sql
-- Check slow queries
SHOW PROCESSLIST;

-- Optimize tables
OPTIMIZE TABLE auth_users;
OPTIMIZE TABLE sessions;

-- Check indexes
SHOW INDEX FROM auth_users;
```

#### **2. Redis Optimization**

```bash
# Check Redis memory usage
redis-cli info memory

# Check Redis performance
redis-cli info stats

# Optimize Redis configuration
redis-cli config set maxmemory-policy allkeys-lru
```

#### **3. Application Optimization**

```bash
# Check Node.js memory usage
node --max-old-space-size=2048 src/index.js

# Enable garbage collection logging
node --trace-gc src/index.js

# Profile application
node --prof src/index.js
```

## 📞 Support

### Getting Help

1. **Check Logs**: Review application and system logs
2. **Health Check**: Verify service health endpoints
3. **Documentation**: Review this deployment guide
4. **Community**: Check GitHub issues and discussions

### Emergency Procedures

#### **Rollback Deployment**

```bash
# Docker rollback
docker tag auth-service:previous auth-service:latest
docker-compose up -d

# Kubernetes rollback
kubectl rollout undo deployment/auth-service -n auth-service

# AWS ECS rollback
aws ecs update-service --cluster production --service auth-service --task-definition auth-service:previous
```

#### **Database Recovery**

```bash
# MySQL backup restore
mysql -h your-db-host -u your-db-user -p your-db-name < backup.sql

# MongoDB backup restore
mongorestore --host your-mongodb-host --db auth_service backup/
```

---

**This deployment guide ensures a robust, scalable, and secure deployment of the AuthService microservice.**
