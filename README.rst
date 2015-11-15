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




***************
What is Auth?
***************
Auth is a module that makes authorization simple and also scalable and powerful.  It also has a beautiful RESTful API for use in micro-service architectures and platforms.  It is originally desinged to use in Appido, a scalable media market in Iran.

It supports Python2.6+ and if you have a mongodb backbone, you need ZERO configurations steps.  Just type ``auth-server`` and press enter!

I use Travis and Codecov to keep myself honest.

*******************
requirements
*******************

You need to access to **mongodb**.  If you are using a remote mongodb,  provide these environment variables:

``MONGO_HOST`` and ``MONGO_PORT``


*******************
Installation
*******************

.. code:: Bash

    pip install auth


*******************
Show me an example
*******************
ok, lets image you have two users, **Jack** and **Sara**.  Sara can cook and Jack can dance. Both can laugh.

You also need to choose a secret key for your application.  Because you may want to use Auth in various tools and each must have a secret key for seperating their scope.

.. code:: Python

    my_secret_key = "pleaSeDoN0tKillMyC_at"
    from auth import Authorization
    cas = Authorization(my_secret_key)

Now, Lets add 3 groups, Cookers, Dancers and Laughers.  Remember that groups are Roles.  So when we create a group, indeed we create a role:

.. code:: Python

    cas.add_group('cookers')
    cas.add_group('dancers')
    cas.add_group('laughers')


Ok, great. You have 3 groups and you need to authorize them to do special things.

.. code:: Python

    cas.add_permission('cookers', 'cook')
    cas.add_permission('dancers', 'dance')
    cas.add_permission('laughers', 'laugh')


Good.  You let cookers to cook and dancers to dance etc...
The final part is to set memberships for Sara and Jack:

.. code:: Python

    cas.add_membership('sara', 'cookers')
    cas.add_membership('sara', 'laughers')
    cas.add_membership('jack', 'dancers')
    cas.add_membership('jack', 'laughers')



That's all we need.  Now lets ensure that jack can dance:

.. code:: Python

    if cas.user_has_permission('jack', 'dance'):
        print('YES!!! Jack can dance.')



**********************
Authirization Methods
**********************

use pydoc to see all methods:

.. code:: Bash

    pydoc auth.Authorization


*******************
RESTful API
*******************
Lets run the server on port 4000:

.. code:: Python

    from auth import api, serve
    serve('localhost', 4000, api)

Or, from version 0.1.2+ you can use this command:

.. code:: Bash

    auth-server


Simple! Authorization server is ready to use.

.. image:: https://raw.githubusercontent.com/ourway/auth/master/docs/API_Usage_Teminal.gif


You can use it via simple curl or using mighty Requests module.  So in you remote application, you can do something like this:

.. code:: Python

    import requests
    secret_key = "pleaSeDoN0tKillMyC_at"
    auth_api = "http://127.0.0.1:4000/api"


Lets create admin group:

.. code:: Python

    requests.post(auth_api+'/role/'+secret_key+'/admin')


And lets make Jack an admin:

.. code:: Python

    requests.post(auth_api+'/permission/'+secret_key+'/jack/admin')

And finally let's check if Sara still can cook:

.. code:: Python

    requests.get(auth_api+'/has_permission/'+secret_key+'/sara/cook')



********************
RESTful API helpers
********************
auth comes with a helper class that makes your life easy.

.. code:: Python

    from auth.client import Client
    service = Client('srv201', 'http://192.168.99.100:4000')
    print(service)
    service.get_roles()
    service.add_role(role='admin')


*******************
API Methods
*******************


.. code:: Bash

    pydoc auth.CAS.REST.service




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

    Get roles that user assinged to

- ``/api/roles/{KEY}`` [GET]

    Get all available roles


*******************
Deployment
*******************

Deploying Auth module in production environment is easy:


.. code:: Bash

    gunicorn auth:api




*******************
Dockerizing
*******************

It's simple:

.. code:: Bash

    docker build -t python/auth-server https://raw.githubusercontent.com/ourway/auth/master/Dockerfile
    docker run --name=auth -e MONGO_HOST='192.168.99.100' -p 4000:4000 -d --restart=always --link=mongodb-server python/auth-server



*******************
Copyright
*******************

- Farsheed Ashouri `@ <mailto:rodmena@me.com>`_


*******************
Documentation
*******************
Feel free to dig into source code.  If you think you can improve the documentation, please do so and send me a pull request.

************************
Unit Tests and Coverage
************************
I am trying to add tests as much as I can, but still there are areas that need improvement.


**********
To DO
**********
- Add Authentication features
- Improve Code Coverage
