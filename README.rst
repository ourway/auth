====================================
Auth | Authorization for Humans
====================================

RESTful, Simple Authorization system with ZERO configuration.

.. image:: https://badge.fury.io/py/auth.svg
    :target: https://badge.fury.io/py/auth

.. image:: https://img.shields.io/pypi/dm/auth.svg
    :target: https://pypi.python.org/pypi/auth

.. image:: https://api.travis-ci.org/ourway/auth.svg
    :target: https://travis-ci.org/ourway/auth

.. image:: https://codecov.io/github/ourway/auth/coverage.svg?branch=master
    :target: https://codecov.io/github/ourway/auth?branch=master

.. note:: **IMPORTANT: Version 0.9.1 is a BREAKING CHANGE**

   This version (0.9.1) replaces MongoDB with SQLite3 as the default database backend.
   If you need MongoDB support, please use the previous version:
   
   .. code:: Bash
   
       pip install auth==0.5.3

***************
What is Auth?
***************
Auth is a modern Python module that makes authorization simple, scalable, and powerful. It provides a beautiful RESTful API for use in micro-service architectures and platforms. 

Built with FastAPI, SQLAlchemy, and Pydantic, it offers type-safe APIs and modern database support with SQLite3 as the default backend.

It supports Python 3.7+ and requires ZERO configuration steps. Just type ``auth-server`` and press enter!

I use Travis and Codecov to keep myself honest.

*******************
Requirements
*******************

Auth uses **SQLite3** as the default database. The database file is automatically created at ``~/.auth.sqlite3``. No additional setup required!

*******************
Installation
*******************

.. code:: Bash

    pip install auth


*******************
Show me an example
*******************
Let's imagine you have two users, **Jack** and **Sara**. Sara can cook and Jack can dance. Both can laugh.

You also need to choose a secret key for your application. The client key **must be a valid UUID4** for new API usage. Each application instance should have its own unique key for proper scope separation.

.. code:: Python

    import uuid
    my_secret_key = str(uuid.uuid4())  # Generate a valid UUID4
    from auth import Authorization
    cas = Authorization(my_secret_key)

Now, let's add 3 groups: Cookers, Dancers and Laughers. Remember that groups are Roles. So when we create a group, indeed we create a role:

.. code:: Python

    cas.add_role('cookers')
    cas.add_role('dancers')
    cas.add_role('laughers')

Great! You have 3 groups and you need to authorize them to do special things.

.. code:: Python

    cas.add_permission('cookers', 'cook')
    cas.add_permission('dancers', 'dance')
    cas.add_permission('laughers', 'laugh')

Good. You let cookers to cook and dancers to dance etc...
The final part is to set memberships for Sara and Jack:

.. code:: Python

    cas.add_membership('sara', 'cookers')
    cas.add_membership('sara', 'laughers')
    cas.add_membership('jack', 'dancers')
    cas.add_membership('jack', 'laughers')

That's all we need. Now let's ensure that Jack can dance:

.. code:: Python

    if cas.user_has_permission('jack', 'dance'):
        print('YES!!! Jack can dance.')

**********************
Authorization Methods
**********************

Use pydoc to see all methods:

.. code:: Bash

    pydoc auth.Authorization

*******************
RESTful API
*******************
Let's run the server on port 4000:

.. code:: Bash

    auth-server

Simple! Authorization server is ready to use.

You can use it via simple curl or using the mighty Requests module. So in your remote application, you can do something like this:

.. code:: Python

    import requests
    import uuid
    secret_key = str(uuid.uuid4())  # Client key must be a valid UUID4
    auth_api = "http://127.0.0.1:4000/api"

Let's create admin role:

.. code:: Python

    requests.post(auth_api+'/role/'+secret_key+'/admin')

And let's add a permission to the admin role:

.. code:: Python

    requests.post(auth_api+'/permission/'+secret_key+'/admin/manage')

And finally let's check if an admin can manage:

.. code:: Python

    response = requests.get(auth_api+'/has_permission/'+secret_key+'/admin/manage')
    print(response.json())

********************
RESTful API helpers
********************
Auth comes with a helper class that makes your life easy.
Note: The client key must be a valid UUID4.

.. code:: Python

    import uuid
    from auth.client import Client
    service = Client(str(uuid.uuid4()), 'http://192.168.99.100:4000')  # Use a valid UUID4
    print(service)
    service.add_role(role='admin')
    service.get_roles()

*******************
API Methods
*******************

.. code:: Bash

    pydoc auth.CAS.REST.service

.. note:: **Important:** All API endpoints require a valid UUID4 as the ``{KEY}`` parameter. Client keys must be valid UUID4 format.

- ``/ping`` [GET]

 Ping API, useful for your monitoring tools

- ``/api/membership/{KEY}/{user}/{role}`` [GET/POST/DELETE]

 Adding, removing and getting membership information.

- ``/api/permission/{KEY}/{role}/{name}`` [GET/POST/DELETE]

 Adding, removing and getting permissions

- ``/api/has_permission/{KEY}/{user}/{name}`` [GET]

 Getting user permission info

- ``/api/role/{KEY}/{role}`` [GET/POST/DELETE]

  Adding, removing and getting roles

- ``/api/which_roles_can/{KEY}/{name}`` [GET]

  For example:  Which roles can send_mail?

- ``/api/which_users_can/{KEY}/{name}`` [GET]

  For example:  Which users can send_mail?

- ``/api/user_permissions/{KEY}/{user}`` [GET]

  Get all permissions that a user has

- ``/api/role_permissions/{KEY}/{role}`` [GET]

  Get all permissions that a role has

- ``/api/user_roles/{KEY}/{user}`` [GET]

    Get roles that user assigned to

- ``/api/roles/{KEY}`` [GET]

    Get all available roles

*******************
Use Cases
*******************

**Microservices Architecture**
- Centralized authorization service for multiple microservices
- Consistent permission management across your entire platform
- Easy integration with FastAPI-based services

**Multi-tenant Applications**
- Separate authorization scopes using different secret keys
- Manage permissions for different organizations or teams
- Scalable role-based access control

**API Gateway Authorization**
- Validate user permissions before routing requests
- Centralized permission checks for API endpoints
- Real-time permission validation

**Content Management Systems**
- Role-based content access control
- User group management for collaborative editing
- Fine-grained permission control for different content types

**Enterprise Applications**
- Department-based access control
- Project team permission management
- Audit trail through comprehensive API logging

**Educational Platforms**
- Student/Teacher role management
- Course access permissions
- Group project collaboration controls

**Healthcare Systems**
- HIPAA-compliant access controls
- Patient data access management
- Staff role-based permissions

*******************
Deployment
*******************

Deploying Auth module in production environment is easy:

.. code:: Bash

    uvicorn auth.main:app --host 0.0.0.0 --port 4000

For production use with multiple workers:

.. code:: Bash

    gunicorn -w 4 -k uvicorn.workers.UvicornWorker auth.main:app

*******************
Dockerizing
*******************

It's simple:

.. code:: Bash

    docker build -t python/auth-server .
    docker run --name=auth -p 4000:4000 -d --restart=always python/auth-server

*******************
Copyright
*******************

- Farsheed Ashouri `@ <mailto:rodmena@me.com>`_

*******************
Documentation
*******************
Feel free to dig into source code. If you think you can improve the documentation, please do so and send me a pull request.

*******************
Architecture
*******************

.. code-block:: mermaid

    graph TB
        subgraph "Client Applications"
            A["Application 1"]
            B["Application 2"]
            C["Application N"]
        end

        subgraph "Auth Service"
            subgraph "API Layer"
                D["FastAPI Routes"]
                E["Request Validation"]
                F["Response Models"]
            end

            subgraph "Service Layer"
                G["AuthorizationService"]
                H["Permission Logic"]
                I["Membership Logic"]
            end

            subgraph "Data Layer"
                J["SQLAlchemy ORM"]
                K["SQLite Database"]
                L["Table Models"]
            end
        end

        subgraph "External Systems"
            M["Microservices"]
            N["API Gateway"]
            O["Monitoring Tools"]
        end

        A --> D
        B --> D
        C --> D
        D --> G
        E --> G
        F --> G
        G --> H
        G --> I
        G --> J
        J --> K
        J --> L
        D --> M
        D --> N
        D --> O

    style D fill:#e1f5fe
    style G fill:#e8f5e8
    style J fill:#fff3e0
    style K fill:#ffebee

**********************************
Remote Access with reTunnel
**********************************

To securely expose your local Auth server to the internet without complex networking setup, we recommend using `reTunnel <https://retunnel.com>`_.

**Installation:**

.. code:: Bash

    pip install retunnel

**Usage:**

To serve your local Auth server running on port 4000:

.. code:: Bash

    retunnel http 4000

This will provide you with a secure public URL that forwards requests to your local Auth server.

**Benefits of using reTunnel:**
- No need to configure firewalls or expose ports directly
- Secure encrypted tunnel
- Easy to use with a simple command
- No complex networking setup required
- Perfect for testing and development

**********
To DO
**********
- Add Authentication features
- Improve Code Coverage
- Add support for additional database backends (PostgreSQL, MySQL)
- Add OpenAPI documentation enhancements

************************
Unit Tests and Coverage
************************
Comprehensive test suite with pytest covering all functionality:

.. code:: Bash

    pytest