========
Security
========

This guide covers security best practices for deploying and using Auth in production.

Authentication
==============

Client Keys
-----------

**Always use UUID4 for client keys:**

.. code-block:: python

    import uuid
    
    # Good: Cryptographically random UUID4
    client_key = str(uuid.uuid4())
    
    # Bad: Predictable keys
    client_key = "my-app-key"  # ✗ Never do this

**Store keys securely:**

.. code-block:: bash

    # Use environment variables
    export AUTH_CLIENT_KEY=$(uuidgen)
    
    # Never hardcode in source
    client_key = "abc-123-def"  # ✗ Insecure

**Rotate keys regularly:**

.. code-block:: bash

    # Generate new key
    NEW_KEY=$(uuidgen)
    
    # Update environment
    export AUTH_CLIENT_KEY=$NEW_KEY
    
    # Restart application

JWT Configuration
-----------------

**Use strong secret keys:**

.. code-block:: bash

    # Generate secure key (minimum 32 characters)
    openssl rand -base64 32
    
    # Set environment variable
    export AUTH_JWT_SECRET_KEY="<generated-key>"

**Configure appropriate token expiration:**

.. code-block:: bash

    # Short-lived access tokens
    export AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
    
    # Longer refresh tokens
    export AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

Authorization
=============

Principle of Least Privilege
-----------------------------

Grant minimum necessary permissions:

.. code-block:: python

    # Good: Specific permissions
    auth.add_permission('editor', 'edit_own_posts')
    auth.add_permission('editor', 'view_own_analytics')
    
    # Bad: Overly broad permissions
    auth.add_permission('editor', 'admin_access')

Role Hierarchy
--------------

Design roles from least to most privileged:

.. code-block:: python

    # Viewer (least privileged)
    auth.add_role('viewer')
    auth.add_permission('viewer', 'view_content')
    
    # Editor (moderate privileges)
    auth.add_role('editor')
    auth.add_permission('editor', 'view_content')
    auth.add_permission('editor', 'edit_content')
    
    # Admin (most privileged)
    auth.add_role('admin')
    auth.add_permission('admin', 'view_content')
    auth.add_permission('admin', 'edit_content')
    auth.add_permission('admin', 'manage_users')
    auth.add_permission('admin', 'delete_content')

Encryption
==========

Field-Level Encryption
----------------------

Enable encryption for sensitive data:

.. code-block:: bash

    # Generate encryption key
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    
    # Enable encryption
    export AUTH_ENABLE_ENCRYPTION=true
    export AUTH_ENCRYPTION_KEY="<generated-key>"

**What gets encrypted:**

- User identifiers in memberships
- Permission names
- Role descriptions (optional)

**Key storage:**

.. code-block:: bash

    # Development: .env file (gitignored)
    echo "AUTH_ENCRYPTION_KEY=..." >> .env
    
    # Production: Secrets manager
    # AWS Secrets Manager
    # HashiCorp Vault
    # Kubernetes Secrets

Transport Security
------------------

**Always use HTTPS in production:**

.. code-block:: nginx

    server {
        listen 443 ssl http2;
        server_name auth.example.com;
        
        ssl_certificate /path/to/cert.pem;
        ssl_certificate_key /path/to/key.pem;
        
        # Modern TLS configuration
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        
        location / {
            proxy_pass http://localhost:5000;
            proxy_set_header X-Forwarded-Proto https;
        }
    }

Database Security
=================

PostgreSQL Hardening
--------------------

**Use strong passwords:**

.. code-block:: sql

    -- Create user with strong password
    CREATE USER authuser WITH PASSWORD 'veryStr0ng&SecureP@ssw0rd!';
    
    -- Grant minimal privileges
    GRANT CONNECT ON DATABASE authdb TO authuser;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authuser;

**Connection security:**

.. code-block:: bash

    # Use SSL connections
    export AUTH_POSTGRESQL_URL="postgresql://authuser:password@localhost:5432/authdb?sslmode=require"

**Network isolation:**

.. code-block:: bash

    # pg_hba.conf - Allow only from application server
    host  authdb  authuser  10.0.1.0/24  scram-sha-256

SQLite Permissions
------------------

.. code-block:: bash

    # Restrict file permissions
    chmod 600 ~/.auth.sqlite3
    
    # Set ownership
    chown authapp:authapp ~/.auth.sqlite3

Input Validation
================

SQL Injection Protection
------------------------

Auth uses SQLAlchemy ORM, which protects against SQL injection:

.. code-block:: python

    # Safe: Parameterized query (ORM)
    auth.add_role(user_input)  # ✓ Automatically sanitized
    
    # Unsafe: Raw SQL (not used in Auth)
    db.execute(f"INSERT INTO roles VALUES ('{user_input}')")  # ✗ Vulnerable

Input Sanitization
------------------

All inputs are validated:

.. code-block:: python

    from auth.sanitizer import sanitize_input
    
    # Sanitization happens automatically
    role_name = sanitize_input(user_provided_role)

**Validation rules:**

- Maximum length limits
- Alphanumeric + allowed special characters only
- No SQL keywords
- No script tags

CORS Configuration
==================

Development
-----------

.. code-block:: bash

    # Allow all origins (development only)
    export AUTH_ALLOW_CORS=true
    export AUTH_CORS_ORIGINS="*"

Production
----------

.. code-block:: bash

    # Restrict to specific origins
    export AUTH_ALLOW_CORS=true
    export AUTH_CORS_ORIGINS="https://app.example.com,https://admin.example.com"

**Example configuration:**

.. code-block:: python

    from flask_cors import CORS
    
    # Specific origins only
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "https://app.example.com",
                "https://admin.example.com"
            ],
            "methods": ["GET", "POST", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

Audit Logging
=============

Enable Comprehensive Logging
-----------------------------

.. code-block:: bash

    export AUTH_ENABLE_AUDIT_LOGGING=true

**Logged events:**

- Role creation/deletion
- Permission grants/revocations
- Membership changes
- Permission checks (optional)

Monitor Audit Logs
------------------

.. code-block:: python

    from auth.audit import query_audit_logs
    
    # Monitor suspicious activity
    recent_logs = query_audit_logs(
        action='delete',
        hours=24
    )
    
    for log in recent_logs:
        if log['entity_type'] == 'role':
            alert_security_team(log)

Secrets Management
==================

Development
-----------

**Use .env files (gitignored):**

.. code-block:: bash

    # .env
    AUTH_JWT_SECRET_KEY=dev-secret-key
    AUTH_ENCRYPTION_KEY=dev-encryption-key
    AUTH_POSTGRESQL_URL=postgresql://user:pass@localhost/authdb

**Never commit secrets:**

.. code-block:: bash

    # .gitignore
    .env
    .env.local
    .env.production
    *.key
    secrets/

Production
----------

**AWS Secrets Manager:**

.. code-block:: python

    import boto3
    import json
    
    def get_secret(secret_name):
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    
    secrets = get_secret('auth/production')
    os.environ['AUTH_JWT_SECRET_KEY'] = secrets['jwt_key']
    os.environ['AUTH_ENCRYPTION_KEY'] = secrets['encryption_key']

**HashiCorp Vault:**

.. code-block:: python

    import hvac
    
    client = hvac.Client(url='https://vault.example.com')
    client.auth.approle.login(role_id='...', secret_id='...')
    
    secrets = client.secrets.kv.v2.read_secret_version(path='auth/config')
    os.environ['AUTH_JWT_SECRET_KEY'] = secrets['data']['data']['jwt_key']

**Kubernetes Secrets:**

.. code-block:: yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: auth-secrets
    type: Opaque
    data:
      jwt-secret: <base64-encoded>
      encryption-key: <base64-encoded>
      db-password: <base64-encoded>

Security Headers
================

Add security headers to responses:

.. code-block:: python

    from flask import Flask
    
    app = Flask(__name__)
    
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

Rate Limiting
=============

Nginx Rate Limiting
-------------------

.. code-block:: nginx

    limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/s;
    
    server {
        location /api/ {
            limit_req zone=auth_limit burst=20 nodelay;
            limit_req_status 429;
            
            proxy_pass http://localhost:5000;
        }
    }

Application-Level Rate Limiting
--------------------------------

.. code-block:: python

    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["100 per hour", "10 per minute"]
    )
    
    @app.route('/api/role/<role>', methods=['POST'])
    @limiter.limit("5 per minute")
    def create_role(role):
        # Rate limited to 5 requests per minute
        pass

Security Checklist
==================

Pre-Production
--------------

- [ ] Generate strong JWT secret key (32+ characters)
- [ ] Enable encryption with Fernet key
- [ ] Configure PostgreSQL with strong password
- [ ] Set up SSL/TLS certificates
- [ ] Configure CORS with specific origins
- [ ] Enable audit logging
- [ ] Set up secrets management
- [ ] Disable debug mode
- [ ] Configure rate limiting
- [ ] Set security headers
- [ ] Review and minimize permissions
- [ ] Test authentication flows
- [ ] Set up monitoring and alerting

Production Monitoring
---------------------

- [ ] Monitor failed authentication attempts
- [ ] Alert on unusual permission grants
- [ ] Track role/permission changes
- [ ] Monitor database connections
- [ ] Set up log aggregation
- [ ] Configure automated backups
- [ ] Test disaster recovery
- [ ] Regular security audits
- [ ] Key rotation schedule
- [ ] Dependency updates

Incident Response
=================

Security Breach Response
------------------------

1. **Immediate Actions:**

   .. code-block:: bash

       # Rotate all keys immediately
       export AUTH_JWT_SECRET_KEY=$(openssl rand -base64 32)
       export AUTH_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
       
       # Restart services
       systemctl restart auth-server

2. **Investigation:**

   .. code-block:: python

       # Query audit logs
       from auth.audit import query_audit_logs
       
       # Find suspicious activity
       logs = query_audit_logs(hours=24)
       suspicious = [log for log in logs if is_suspicious(log)]

3. **Remediation:**

   - Revoke compromised permissions
   - Reset affected user roles
   - Update security configurations
   - Notify affected users

Regular Security Tasks
======================

Weekly
------

- Review audit logs
- Check for failed auth attempts
- Monitor system resources

Monthly
-------

- Rotate encryption keys
- Update dependencies
- Review user permissions
- Backup verification

Quarterly
---------

- Security audit
- Penetration testing
- Access review
- Update documentation

Next Steps
==========

- :doc:`encryption` - Encryption details
- :doc:`audit_logging` - Audit logging
- :doc:`deployment` - Secure deployment
- :doc:`production` - Production hardening
