==========
Deployment
==========

This guide covers deploying Auth in various environments.

Deployment Options
==================

1. Standalone Server
2. Docker Container
3. Kubernetes
4. Systemd Service
5. Cloud Platforms (AWS, GCP, Azure)

Standalone Server
=================

Using Waitress (Recommended)
-----------------------------

.. code-block:: bash

    pip install waitress
    waitress-serve --host=0.0.0.0 --port=5000 --threads=10 auth.main:app

Using Gunicorn
--------------

.. code-block:: bash

    pip install gunicorn
    gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 auth.main:app

Production Configuration
------------------------

.. code-block:: bash

    # gunicorn_config.py
    bind = "0.0.0.0:5000"
    workers = 4
    worker_class = "sync"
    timeout = 120
    keepalive = 5
    max_requests = 1000
    max_requests_jitter = 100

Run with:

.. code-block:: bash

    gunicorn -c gunicorn_config.py auth.main:app

Docker Deployment
=================

Dockerfile
----------

.. code-block:: dockerfile

    FROM python:3.11-slim
    
    WORKDIR /app
    
    # Install dependencies
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    
    # Copy application
    COPY . .
    
    # Create non-root user
    RUN useradd -m -u 1000 authuser && chown -R authuser:authuser /app
    USER authuser
    
    EXPOSE 5000
    
    CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "auth.main:app"]

Build and Run
-------------

.. code-block:: bash

    # Build
    docker build -t auth:latest .
    
    # Run
    docker run -d \
      --name auth-server \
      -p 5000:5000 \
      -e AUTH_DATABASE_TYPE=postgresql \
      -e AUTH_POSTGRESQL_URL=postgresql://user:pass@db:5432/authdb \
      auth:latest

Docker Compose
--------------

.. code-block:: yaml

    version: '3.8'
    
    services:
      postgres:
        image: postgres:15
        environment:
          POSTGRES_DB: authdb
          POSTGRES_USER: authuser
          POSTGRES_PASSWORD: ${DB_PASSWORD}
        volumes:
          - postgres_data:/var/lib/postgresql/data
        networks:
          - auth_network
    
      auth:
        build: .
        ports:
          - "5000:5000"
        environment:
          AUTH_DATABASE_TYPE: postgresql
          AUTH_POSTGRESQL_URL: postgresql://authuser:${DB_PASSWORD}@postgres:5432/authdb
          AUTH_JWT_SECRET_KEY: ${JWT_SECRET}
          AUTH_ENABLE_ENCRYPTION: "true"
          AUTH_ENCRYPTION_KEY: ${ENCRYPTION_KEY}
        depends_on:
          - postgres
        networks:
          - auth_network
    
    volumes:
      postgres_data:
    
    networks:
      auth_network:

Kubernetes Deployment
=====================

ConfigMap
---------

.. code-block:: yaml

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: auth-config
    data:
      AUTH_DATABASE_TYPE: "postgresql"
      AUTH_SERVER_HOST: "0.0.0.0"
      AUTH_SERVER_PORT: "5000"

Secret
------

.. code-block:: yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: auth-secrets
    type: Opaque
    stringData:
      jwt-secret: your-jwt-secret-here
      encryption-key: your-encryption-key-here
      db-url: postgresql://user:pass@postgres:5432/authdb

Deployment
----------

.. code-block:: yaml

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: auth-server
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: auth
      template:
        metadata:
          labels:
            app: auth
        spec:
          containers:
          - name: auth
            image: auth:latest
            ports:
            - containerPort: 5000
            envFrom:
            - configMapRef:
                name: auth-config
            env:
            - name: AUTH_JWT_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: jwt-secret
            - name: AUTH_ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: encryption-key
            - name: AUTH_POSTGRESQL_URL
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: db-url
            resources:
              requests:
                memory: "256Mi"
                cpu: "250m"
              limits:
                memory: "512Mi"
                cpu: "500m"

Service
-------

.. code-block:: yaml

    apiVersion: v1
    kind: Service
    metadata:
      name: auth-service
    spec:
      selector:
        app: auth
      ports:
      - port: 80
        targetPort: 5000
      type: LoadBalancer

Systemd Service
===============

Service File
------------

.. code-block:: ini

    # /etc/systemd/system/auth.service
    [Unit]
    Description=Auth Authorization Server
    After=network.target postgresql.service
    
    [Service]
    Type=simple
    User=authuser
    WorkingDirectory=/opt/auth
    Environment="PATH=/opt/auth/venv/bin"
    EnvironmentFile=/opt/auth/.env
    ExecStart=/opt/auth/venv/bin/waitress-serve --host=0.0.0.0 --port=5000 auth.main:app
    Restart=always
    RestartSec=10
    
    [Install]
    WantedBy=multi-user.target

Enable and Start
----------------

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl enable auth.service
    sudo systemctl start auth.service
    sudo systemctl status auth.service

Cloud Platforms
===============

AWS Deployment
--------------

Using Elastic Beanstalk:

.. code-block:: bash

    # Install EB CLI
    pip install awsebcli
    
    # Initialize
    eb init -p python-3.11 auth-app
    
    # Create environment
    eb create auth-production
    
    # Deploy
    eb deploy

Using ECS:

.. code-block:: json

    {
      "family": "auth-task",
      "containerDefinitions": [{
        "name": "auth",
        "image": "your-ecr-repo/auth:latest",
        "memory": 512,
        "cpu": 256,
        "essential": true,
        "portMappings": [{
          "containerPort": 5000,
          "protocol": "tcp"
        }],
        "environment": [
          {"name": "AUTH_DATABASE_TYPE", "value": "postgresql"}
        ],
        "secrets": [
          {"name": "AUTH_JWT_SECRET_KEY", "valueFrom": "arn:aws:secretsmanager:..."}
        ]
      }]
    }

Next Steps
==========

- :doc:`production` - Production best practices
- :doc:`security` - Security hardening
- :doc:`configuration` - Configuration options
