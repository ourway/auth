# Database Connection Pooling - Enterprise Configuration

## Overview

The auth service has been optimized for high-volume enterprise usage with proper connection pooling, singleton pattern implementation, and comprehensive monitoring.

## Key Features

### 1. Thread-Safe Singleton Pattern

The `DatabaseEngine` class uses a metaclass-based singleton pattern to ensure:
- **One engine instance per Gunicorn worker** (per process)
- **Thread-safe initialization** with locking mechanism
- **Prevents connection pool exhaustion** from multiple engine instances

### 2. Optimized Connection Pool Configuration

#### PostgreSQL Configuration (8 Gunicorn Workers)

```python
pool_size = 5          # Base connections per worker
max_overflow = 5       # Additional connections when needed
# Total per worker: 10 connections maximum
# Total across 8 workers: 80 connections maximum
```

**Why these numbers?**
- PostgreSQL `max_connections` = 220 (verified)
- Auth service max usage: 80 connections
- Leaves 140 connections for other services and admin tools
- Prevents connection exhaustion under high load

#### Connection Pool Features

- **QueuePool**: Efficient FIFO connection pooling
- **pool_pre_ping**: Verifies connections before use (prevents stale connections)
- **pool_recycle**: Connections recycled after 1 hour
- **pool_timeout**: 30 seconds wait time for available connection
- **Statement timeout**: 30 seconds (prevents long-running queries)

### 3. Connection Pool Monitoring

#### Health Endpoint

```bash
curl https://auth.rodmena.app/health
```

Returns:
```json
{
  "status": "healthy",
  "database": {
    "pool_size": 5,
    "checked_out": 0,
    "available": 5,
    "overflow": 0,
    "total_connections": 2
  }
}
```

**Metrics Explained:**
- `pool_size`: Base pool size per worker
- `checked_out`: Currently active connections
- `available`: Connections ready for use
- `overflow`: Extra connections beyond pool_size
- `total_connections`: Total connections created

#### Database-Level Monitoring

Check active connections from PostgreSQL:

```bash
PGPASSWORD=auth_pass123 psql -h localhost -U auth_user -d auth_db -c \
  "SELECT application_name, state, COUNT(*) \
   FROM pg_stat_activity \
   WHERE datname = 'auth_db' \
   GROUP BY application_name, state;"
```

### 4. Connection Pool Events

The system logs connection pool events at DEBUG level:

- **connect**: New connection established
- **checkout**: Connection retrieved from pool
- **checkin**: Connection returned to pool
- **invalidate**: Connection marked as invalid
- **soft_invalidate**: Connection marked for refresh

Enable debug logging to see these events:

```python
import logging
logging.getLogger('auth.database').setLevel(logging.DEBUG)
```

## Performance Characteristics

### Under Normal Load

- **Connections per worker**: 1-3 active
- **Total system connections**: 10-20
- **Pool efficiency**: High (most connections reused)

### Under High Load

- **Connections per worker**: Up to 10 (pool_size + max_overflow)
- **Total system connections**: Up to 80 across all workers
- **Overflow behavior**: Creates temporary connections, automatically cleaned up

### Connection Lifecycle

1. **Request arrives** → Worker checks out connection from pool
2. **Request processed** → Worker returns connection to pool
3. **Connection idle** → Kept alive for reuse (up to 1 hour)
4. **Connection stale** → Pre-ping detects, connection refreshed
5. **Connection aged** → Recycled after 1 hour

## Troubleshooting

### Too Many Connections

**Symptom**: `PoolTimeout` errors or slow response times

**Check**:
```bash
curl https://auth.rodmena.app/health
```

If `checked_out` consistently equals `pool_size + overflow`, you're hitting limits.

**Solutions**:
1. Increase `pool_size` in `auth/database.py` (carefully!)
2. Reduce number of Gunicorn workers
3. Investigate slow queries (check `statement_timeout`)
4. Check for connection leaks (all sessions should use `with get_db()`)

### Connection Leaks

**Symptom**: Steadily increasing `checked_out` connections

**Check**:
```python
# In code - always use context manager
with get_db() as db:
    # Your code here
    pass  # Connection automatically closed
```

**Anti-pattern** (causes leaks):
```python
# DON'T DO THIS
db = SessionLocal()
# ... code ...
# Forgot to close!
```

### Stale Connections

**Symptom**: Random database errors after idle periods

**Already handled by**:
- `pool_pre_ping=True`: Tests connections before use
- `pool_recycle=3600`: Recycles connections after 1 hour

## Configuration for Different Scenarios

### High Traffic (100+ requests/second)

```python
# Increase pool size, but keep total < PostgreSQL max_connections
pool_size = 10
max_overflow = 10
# With 8 workers: 160 total connections max
```

Update PostgreSQL:
```sql
ALTER SYSTEM SET max_connections = 250;
SELECT pg_reload_conf();
```

### Low Memory Environment

```python
# Reduce pool size to save memory
pool_size = 3
max_overflow = 2
# With 8 workers: 40 total connections max
```

### Single Worker (Development)

```python
# Can use larger pool per worker
pool_size = 10
max_overflow = 20
```

## Monitoring Recommendations

### Application-Level

1. **Add metrics collection**:
   ```python
   from auth.database import get_pool_status

   stats = get_pool_status()
   # Send to monitoring system (Prometheus, Datadog, etc.)
   ```

2. **Monitor `/health` endpoint**:
   - Set up alerts for `checked_out / total_connections > 0.8`
   - Track `overflow` spikes

### Database-Level

1. **Monitor active connections**:
   ```sql
   SELECT COUNT(*) FROM pg_stat_activity WHERE datname = 'auth_db';
   ```

2. **Monitor slow queries**:
   ```sql
   SELECT pid, now() - query_start as duration, query
   FROM pg_stat_activity
   WHERE state = 'active' AND now() - query_start > interval '5 seconds';
   ```

3. **Enable PostgreSQL logging**:
   ```sql
   ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Log queries > 1s
   ```

## Best Practices

1. **Always use context managers**: `with get_db() as db:`
2. **Keep transactions short**: Don't hold connections during I/O
3. **Monitor pool statistics**: Regular health checks
4. **Load test before production**: Verify pool sizing
5. **Set connection limits**: Prevent runaway connection usage

## Load Testing

Test connection pooling with:

```bash
# Run 100 concurrent requests
ab -n 1000 -c 100 -H "Authorization: Bearer $(uuidgen)" \
   https://auth.rodmena.app/api/roles

# Monitor during test
watch -n 1 'curl -s https://auth.rodmena.app/health | jq .'
```

Expected behavior:
- `checked_out` should fluctuate but not stay maxed out
- `overflow` should be minimal under normal load
- All connections should return to pool after requests complete

## Capacity Planning

### Current Configuration (8 workers)

- **Theoretical max**: 80 connections
- **Typical usage**: 10-20 connections
- **Peak capacity**: ~500-1000 requests/second
- **PostgreSQL headroom**: 140 connections available

### Scaling Guidelines

| Workers | Pool Size | Max Overflow | Total Max | Recommended For |
|---------|-----------|--------------|-----------|-----------------|
| 4       | 5         | 5            | 40        | Light load      |
| 8       | 5         | 5            | 80        | **Current**     |
| 16      | 5         | 5            | 160       | Heavy load      |
| 32      | 3         | 2            | 160       | Very high load  |

**Note**: Increase PostgreSQL `max_connections` before adding workers!

## See Also

- [SQLAlchemy Connection Pooling](https://docs.sqlalchemy.org/en/20/core/pooling.html)
- [PostgreSQL Connection Pooling Best Practices](https://www.postgresql.org/docs/current/runtime-config-connection.html)
- [Gunicorn Worker Configuration](https://docs.gunicorn.org/en/stable/settings.html#workers)
