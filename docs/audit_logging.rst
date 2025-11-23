===============
Audit Logging
===============

Auth provides comprehensive audit logging for compliance and security monitoring.

Overview
========

What is Logged
--------------

Every authorization change is recorded:

- Role creation/deletion
- Permission grants/revokes  
- Membership additions/removals
- Configuration changes

Audit Log Format
----------------

Each log entry contains:

- **client_key** - Which client made the change
- **action** - Type of operation (create, delete, grant, revoke)
- **entity_type** - What was modified (role, permission, membership)
- **entity_id** - Identifier of the entity
- **details** - Additional context (JSON)
- **timestamp** - When the change occurred

Configuration
=============

Enable Audit Logging
--------------------

.. code-block:: bash

    export AUTH_ENABLE_AUDIT_LOGGING=true

Audit logging is enabled by default.

Database Schema
---------------

.. code-block:: sql

    CREATE TABLE auth_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_key TEXT NOT NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_client_key (client_key),
        INDEX idx_timestamp (timestamp),
        INDEX idx_action (action)
    );

Querying Audit Logs
===================

Python API
----------

.. code-block:: python

    from auth.audit import query_audit_logs
    
    # Get all logs for a client
    logs = query_audit_logs(client_key='abc-123')
    
    # Get logs by action
    deletions = query_audit_logs(action='delete')
    
    # Get logs by entity type
    role_changes = query_audit_logs(entity_type='role')
    
    # Get recent logs (last 24 hours)
    recent = query_audit_logs(hours=24)
    
    # Get logs in date range
    logs = query_audit_logs(
        start_date='2025-01-01',
        end_date='2025-01-31'
    )

SQL Queries
-----------

.. code-block:: sql

    -- All permission grants in last week
    SELECT * FROM auth_audit_log
    WHERE action = 'grant'
      AND entity_type = 'permission'
      AND timestamp > datetime('now', '-7 days')
    ORDER BY timestamp DESC;
    
    -- All changes by specific client
    SELECT * FROM auth_audit_log
    WHERE client_key = 'abc-123'
    ORDER BY timestamp DESC;
    
    -- Role deletions
    SELECT * FROM auth_audit_log
    WHERE action = 'delete'
      AND entity_type = 'role';

Monitoring
==========

Real-time Monitoring
--------------------

.. code-block:: python

    import time
    from auth.audit import query_audit_logs
    
    def monitor_audit_logs():
        last_check = time.time()
        
        while True:
            # Check for new logs every minute
            time.sleep(60)
            
            logs = query_audit_logs(since_timestamp=last_check)
            for log in logs:
                if is_suspicious(log):
                    alert_security_team(log)
            
            last_check = time.time()

Alerting
--------

.. code-block:: python

    def is_suspicious(log):
        """Detect suspicious activities"""
        suspicious_patterns = [
            # Multiple rapid changes
            {'action': 'delete', 'count_threshold': 10, 'window_minutes': 5},
            # Permission grants to admin role
            {'entity_type': 'permission', 'entity_id': 'admin'},
            # After-hours changes
            {'hour_range': (22, 6)},
        ]
        
        # Implement detection logic
        return check_patterns(log, suspicious_patterns)
    
    def alert_security_team(log):
        """Send alert"""
        send_email(
            to='security@example.com',
            subject='Suspicious Auth Activity',
            body=f'Suspicious activity detected: {log}'
        )

Compliance
==========

GDPR Compliance
---------------

Audit logs support GDPR requirements:

.. code-block:: python

    def export_user_audit_trail(user_email):
        """Export all audit logs related to a user"""
        logs = query_audit_logs(entity_id=user_email)
        
        return {
            'user': user_email,
            'audit_trail': [
                {
                    'timestamp': log['timestamp'],
                    'action': log['action'],
                    'details': log['details']
                }
                for log in logs
            ]
        }

SOC 2 Compliance
----------------

Audit logs provide evidence for SOC 2 controls:

.. code-block:: python

    def generate_access_report(start_date, end_date):
        """Generate access control report"""
        logs = query_audit_logs(
            start_date=start_date,
            end_date=end_date
        )
        
        return {
            'period': f'{start_date} to {end_date}',
            'total_changes': len(logs),
            'by_action': group_by(logs, 'action'),
            'by_client': group_by(logs, 'client_key'),
            'critical_changes': filter_critical(logs)
        }

Retention
=========

Log Retention Policy
--------------------

.. code-block:: python

    def cleanup_old_logs(retention_days=90):
        """Remove logs older than retention period"""
        from auth.database import SessionLocal
        from auth.models.sql import AuthAuditLog
        from datetime import datetime, timedelta
        
        db = SessionLocal()
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            deleted = db.query(AuthAuditLog).filter(
                AuthAuditLog.timestamp < cutoff_date
            ).delete()
            
            db.commit()
            print(f"Deleted {deleted} old audit logs")
        finally:
            db.close()

Archival
--------

.. code-block:: python

    def archive_old_logs(archive_days=30):
        """Archive logs to S3 before deletion"""
        import boto3
        import json
        
        logs = query_audit_logs(older_than_days=archive_days)
        
        s3 = boto3.client('s3')
        archive_file = f'audit_logs_{datetime.now().isoformat()}.json'
        
        s3.put_object(
            Bucket='auth-audit-archives',
            Key=archive_file,
            Body=json.dumps(logs, indent=2)
        )
        
        # Now safe to delete
        cleanup_old_logs(retention_days=archive_days)

Next Steps
==========

- :doc:`security` - Security best practices
- :doc:`production` - Production monitoring
- :doc:`troubleshooting` - Common issues
