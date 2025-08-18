# Circuit Breaker Pattern - Production Ready with Opossum

A production-ready circuit breaker implementation using Netflix's Opossum library.

## 🎯 What is Circuit Breaker?

Circuit breaker prevents cascading failures in microservices by:
- **Detecting failures** when services are down
- **Opening circuit** to stop requests when threshold is reached
- **Allowing recovery** after timeout period
- **Providing fallbacks** for better user experience

## 🔌 How It Works

### 3 States:
```
🟢 CLOSED: Normal operation, requests pass through
🟡 OPEN: Service failing, requests are rejected
🔄 HALF_OPEN: Testing if service recovered
```

### Flow:
1. **Service calls** pass through normally (CLOSED)
2. **Failures accumulate** until threshold is reached
3. **Circuit opens** and rejects all requests
4. **After timeout**, circuit moves to HALF_OPEN
5. **Test request** to see if service recovered
6. **Circuit closes** if successful, stays open if failed

## 💻 Usage Examples

### Basic Usage:
```javascript
import CircuitBreaker from 'opossum';

const circuitBreaker = new CircuitBreaker(serviceCall, {
  timeout: 5000,                    // 5 seconds timeout
  errorThresholdPercentage: 50,     // Open after 50% errors
  resetTimeout: 20000,              // Wait 20 seconds before testing
  name: 'ServiceName'               // Service name for logging
});

// Execute with circuit breaker protection
const result = await circuitBreaker.fire();
```

### gRPC Usage:
```javascript
import CircuitBreaker from 'opossum';

const grpcCircuitBreaker = new CircuitBreaker(async (grpcCall) => {
  return grpcCall();
}, {
  timeout: 5000,                    // 5 seconds timeout
  errorThresholdPercentage: 50,     // Open after 50% errors
  resetTimeout: 20000,              // Wait 20 seconds before testing
  name: 'AuthService'               // Service name for logging
});

// Execute gRPC call with circuit breaker
const result = await grpcCircuitBreaker.fire(async () => {
  return grpcClient.method();
});
```

## ⚙️ Configuration Options

```javascript
const options = {
  timeout: 5000,                    // Request timeout in milliseconds
  errorThresholdPercentage: 50,     // Percentage of errors to open circuit
  resetTimeout: 20000,              // Time to wait before testing recovery
  name: 'ServiceName',              // Service name for logging
  volumeThreshold: 10,              // Minimum requests before circuit can open
  rollingCountTimeout: 10000,       // Rolling window for error counting
  rollingCountBuckets: 10           // Number of buckets in rolling window
};
```

## 📊 Monitoring & Events

### Event Listeners:
```javascript
circuitBreaker.on('open', () => {
  console.log('🔄 Circuit breaker opened');
});

circuitBreaker.on('close', () => {
  console.log('✅ Circuit breaker closed');
});

circuitBreaker.on('halfOpen', () => {
  console.log('🔄 Circuit breaker half-open');
});

circuitBreaker.on('fallback', (result) => {
  console.log('🔄 Fallback executed');
});

circuitBreaker.on('timeout', () => {
  console.log('⏰ Request timeout');
});

circuitBreaker.on('reject', () => {
  console.log('🚫 Request rejected');
});
```

### Get Statistics:
```javascript
const stats = circuitBreaker.stats;
console.log(stats);
// {
//   totalCount: 100,
//   errorCount: 5,
//   successCount: 95,
//   fallbackCount: 0,
//   timeoutCount: 0,
//   rejectCount: 0
// }
```

### Health Check:
```javascript
// Circuit breaker health is included in /health endpoint
const health = await checkCircuitBreaker();
// Returns: { status: 'healthy', details: {...} }
```

## 🚀 Benefits of Opossum

1. **Production Proven**: Netflix's battle-tested implementation
2. **Advanced Features**: Rolling counters, percent-based thresholds
3. **Rich Metrics**: Comprehensive statistics and monitoring
4. **Event System**: Real-time notifications for all state changes
5. **Configurable**: Flexible options for different use cases
6. **Community Support**: Active development and maintenance

## 🔧 For 2 Developers

- **Simple**: Easy to understand and use
- **Production Ready**: Netflix-level reliability
- **Maintainable**: Well-documented and supported
- **Scalable**: Works for 2 services or 200 services

## 📝 Example Scenarios

### Scenario 1: Service Down
```
1. User Service calls Auth Service
2. Auth Service is down (50% errors)
3. Circuit opens, requests rejected
4. Fast failure response to user
5. After 20 seconds, circuit tests recovery
6. Auth Service still down, circuit stays open
```

### Scenario 2: Service Recovery
```
1. Circuit is OPEN (Auth Service down)
2. After 20 seconds, circuit moves to HALF_OPEN
3. Test request to Auth Service
4. Auth Service responds successfully
5. Circuit closes, normal operation resumes
```

## 🌟 Why Opossum?

- **Industry Standard**: Netflix's production implementation
- **Battle Tested**: Millions of requests per day
- **Rich Features**: Advanced patterns and metrics
- **Active Development**: Regular updates and improvements
- **Community**: Large ecosystem and support

Perfect for production microservices! 🎯
