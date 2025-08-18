# 🚀 Port Configuration Guide - AuthService

## 🚨 **Critical: Port Conflicts Resolved**

This document explains the port configuration to avoid conflicts between your microservices.

## 📍 **Service Port Mapping**

| Service            | HTTP Port | gRPC Port | Purpose                        |
| ------------------ | --------- | --------- | ------------------------------ |
| **AuthService**    | 3001      | 50050     | Authentication & Authorization |
| **UserService**    | 3002      | 50051     | User Management                |
| **Other Services** | 3003+     | 50052+    | Additional microservices       |

## 🔧 **Port Configuration Details**

### **AuthService Configuration**

```bash
# HTTP Server
PORT=3001

# gRPC Server (this service)
GRPC_SERVER_PORT=50050

# gRPC Client (connecting to UserService)
GRPC_USER_SERVICE_PORT=50051
```

### **UserService Configuration**

```bash
# HTTP Server
PORT=3002

# gRPC Server (this service)
GRPC_SERVER_PORT=50051

# gRPC Client (connecting to AuthService)
GRPC_AUTH_SERVICE_PORT=50050
```

## 🚨 **Common Port Conflicts & Solutions**

### **Problem 1: Both services using port 50052**

```
❌ Error: listen EADDRINUSE: address already in use ::1:50052
```

**Solution**:

- AuthService: Use port 50050
- UserService: Use port 50051

### **Problem 2: HTTP port conflicts**

```
❌ Error: listen EADDRINUSE: address already in use :::3001
```

**Solution**:

- AuthService: Port 3001
- UserService: Port 3002

## 🚀 **Quick Setup Commands**

### **1. Setup AuthService**

```bash
cd authService
npm run setup:dev
```

### **2. Setup UserService**

```bash
cd userService
npm run setup:dev
```

### **3. Start Services (in separate terminals)**

```bash
# Terminal 1 - AuthService
cd authService
npm run dev

# Terminal 2 - UserService
cd userService
npm run dev
```

## 🔍 **Verification Commands**

### **Check if ports are in use**

```bash
# Windows
netstat -an | findstr :3001
netstat -an | findstr :3002
netstat -an | findstr :50050
netstat -an | findstr :50051

# Linux/Mac
netstat -an | grep :3001
netstat -an | grep :3002
netstat -an | grep :50050
netstat -an | grep :50051
```

### **Test service connectivity**

```bash
# Test AuthService HTTP
curl http://localhost:3001/health

# Test UserService HTTP
curl http://localhost:3002/health
```

## 📋 **Environment Variables Summary**

### **AuthService (.env)**

```bash
NODE_ENV=development
PORT=3001
GRPC_SERVER_PORT=50050
GRPC_USER_SERVICE_PORT=50051
```

### **UserService (.env)**

```bash
NODE_ENV=development
PORT=3002
GRPC_SERVER_PORT=50051
GRPC_AUTH_SERVICE_PORT=50050
```

## 🚨 **Troubleshooting**

### **Port Already in Use**

1. Check what's using the port: `netstat -an | findstr :PORT`
2. Stop the conflicting service
3. Or change the port in your .env file

### **gRPC Connection Failed**

1. Verify both services are running
2. Check port numbers match
3. Ensure no firewall blocking connections

### **Service Won't Start**

1. Check .env file exists
2. Verify port configuration
3. Check database connections
4. Review error logs

## 💡 **Best Practices**

1. **Always use different ports** for different services
2. **Document port assignments** in your team
3. **Use environment variables** for port configuration
4. **Test connectivity** before starting development
5. **Keep port ranges organized** (3000s for HTTP, 50050s for gRPC)

## 🔗 **Service Communication Flow**

```
┌─────────────┐    HTTP:3001    ┌─────────────┐
│             │◄───────────────►│             │
│ AuthService │                 │   Client    │
│             │                 │             │
└─────────────┘                 └─────────────┘
       │                               │
       │ gRPC:50050                    │
       ▼                               │
┌─────────────┐    gRPC:50051    ┌─────────────┐
│             │◄───────────────►│             │
│ AuthService │                 │ UserService │
│             │                 │             │
└─────────────┘                 └─────────────┘
```

## 📞 **Need Help?**

If you're still experiencing port conflicts:

1. **Check the logs** for specific error messages
2. **Verify port assignments** in both .env files
3. **Restart both services** after configuration changes
4. **Use different ports** if conflicts persist

Remember: **Port conflicts are the most common issue** when running multiple microservices locally! 🎯
