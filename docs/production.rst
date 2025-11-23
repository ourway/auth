=================
Production Guide
=================

Best practices for running Auth in production.

Pre-Production Checklist
=========================

Database
--------

- [ ] Use PostgreSQL (not SQLite)
- [ ] Configure connection pooling
- [ ] Set up automated backups
- [ ] Enable WAL mode
- [ ] Configure max connections

Security
--------

- [ ] Generate strong JWT secret (32+ chars)
- [ ] Enable encryption
- [ ] Configure HTTPS/SSL
- [ ] Set up firewall rules
- [ ] Disable debug mode
- [ ] Configure CORS properly
- [ ] Set security headers

Monitoring
----------

- [ ] Set up health checks
- [ ] Configure logging
- [ ] Set up error tracking
- [ ] Configure metrics collection
- [ ] Set up alerts

Performance
-----------

- [ ] Configure worker processes
- [ ] Set up caching
- [ ] Optimize database indexes
- [ ] Configure rate limiting

See :doc:`deployment` and :doc:`security` for detailed configuration.

Next Steps
==========

- :doc:`deployment` - Deployment strategies
- :doc:`security` - Security practices
- :doc:`troubleshooting` - Common issues
