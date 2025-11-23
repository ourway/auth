=============
Authorization
=============

.. automodule:: auth
   :members:
   :undoc-members:
   :show-inheritance:

Authorization Class
===================

.. autoclass:: auth.Authorization
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __init__

Methods
=======

Role Management
---------------

.. automethod:: auth.Authorization.add_role
.. automethod:: auth.Authorization.del_role
.. automethod:: auth.Authorization.roles

Permission Management
---------------------

.. automethod:: auth.Authorization.add_permission
.. automethod:: auth.Authorization.del_permission
.. automethod:: auth.Authorization.has_permission
.. automethod:: auth.Authorization.get_permissions

Membership Management
---------------------

.. automethod:: auth.Authorization.add_membership
.. automethod:: auth.Authorization.del_membership
.. automethod:: auth.Authorization.has_membership
.. automethod:: auth.Authorization.get_role_members

User Queries
------------

.. automethod:: auth.Authorization.user_has_permission
.. automethod:: auth.Authorization.get_user_permissions
.. automethod:: auth.Authorization.get_user_roles

Reverse Queries
---------------

.. automethod:: auth.Authorization.which_users_can
.. automethod:: auth.Authorization.which_roles_can
