# Python Usage Examples

Comprehensive examples for using the Auth library in Python applications.

## Table of Contents

- [Installation](#installation)
- [Basic Setup](#basic-setup)
- [Role Management](#role-management)
- [Permission Management](#permission-management)
- [User Management](#user-management)
- [Permission Checking](#permission-checking)
- [Advanced Queries](#advanced-queries)
- [Using the REST Client](#using-the-rest-client)
- [Custom Database Connection](#custom-database-connection)
- [Error Handling](#error-handling)
- [Real-World Examples](#real-world-examples)

## Installation

```bash
pip install -r requirements.txt
```

## Basic Setup

### Create an Authorization Instance

```python
import uuid
from auth import Authorization

# Generate a unique client key (UUID4)
client_key = str(uuid.uuid4())

# Create authorization instance
# Uses the configured database (SQLite or PostgreSQL)
auth = Authorization(client_key)
```

### Using a Custom Database Connection

For testing or when you need more control:

```python
import uuid
from auth.dal.authorization_sqlite import Authorization
from auth.models.sqlite import make_db_connection

client_key = str(uuid.uuid4())

# Create custom connection (e.g., in-memory for testing)
conn = make_db_connection()

# Pass connection to Authorization
auth = Authorization(client_key, conn=conn)
```

## Role Management

### Creating Roles

```python
# Create a role
success = auth.add_role('admin', description='Administrator with full access')
print(f"Admin role created: {success}")

# Create multiple roles
roles = [
    ('editor', 'Content editor'),
    ('viewer', 'Read-only access'),
    ('moderator', 'Content moderation')
]

for role_name, description in roles:
    auth.add_role(role_name, description)
```

### Listing Roles

```python
# Get all roles
all_roles = auth.roles
for role in all_roles:
    print(f"Role: {role['role']}")
    # Note: description is stored but not returned in roles property
```

### Deleting Roles

```python
# Delete a role (also removes all memberships and permissions)
success = auth.del_role('viewer')
print(f"Viewer role deleted: {success}")
```

### Checking if Role Exists

```python
# Check if role exists
role_obj = auth.get_role('admin')
if role_obj:
    print(f"Admin role exists: {role_obj}")
else:
    print("Admin role not found")
```

## Permission Management

### Adding Permissions to Roles

```python
# Add single permission
auth.add_permission('admin', 'manage_users')

# Add multiple permissions to a role
admin_permissions = [
    'manage_users',
    'manage_roles',
    'manage_permissions',
    'view_audit_logs',
    'edit_content',
    'delete_content'
]

for permission in admin_permissions:
    auth.add_permission('admin', permission)

# Add permissions to editor role
editor_permissions = ['edit_content', 'view_content', 'create_content']
for permission in editor_permissions:
    auth.add_permission('editor', permission)
```

### Checking Role Permissions

```python
# Check if role has specific permission
has_perm = auth.has_permission('admin', 'manage_users')
print(f"Admin can manage users: {has_perm}")

# Check multiple permissions
permissions_to_check = ['edit_content', 'delete_content', 'manage_roles']
for perm in permissions_to_check:
    has_it = auth.has_permission('editor', perm)
    print(f"Editor has {perm}: {has_it}")
```

### Getting Role Permissions

```python
# Get all permissions for a role
permissions = auth.get_permissions('admin')
perm_names = [p['name'] for p in permissions]
print(f"Admin permissions: {perm_names}")
```

### Removing Permissions

```python
# Remove permission from role
success = auth.del_permission('editor', 'delete_content')
print(f"Permission removed: {success}")
```

## User Management

### Adding Users to Roles

```python
# Add user to role
auth.add_membership('alice@example.com', 'admin')
auth.add_membership('bob@example.com', 'editor')
auth.add_membership('charlie@example.com', 'viewer')

# Add user to multiple roles
user = 'dave@example.com'
roles = ['editor', 'moderator']
for role in roles:
    auth.add_membership(user, role)
```

### Checking User Membership

```python
# Check if user is in a role
is_admin = auth.has_membership('alice@example.com', 'admin')
print(f"Alice is admin: {is_admin}")

# Check user membership in multiple roles
user = 'dave@example.com'
for role in ['admin', 'editor', 'moderator']:
    is_member = auth.has_membership(user, role)
    print(f"{user} is {role}: {is_member}")
```

### Getting User Roles

```python
# Get all roles for a user
user_roles = auth.get_user_roles('dave@example.com')
for role_info in user_roles:
    print(f"User: {role_info['user']}, Role: {role_info['role']}")
```

### Removing Users from Roles

```python
# Remove user from role
success = auth.del_membership('charlie@example.com', 'viewer')
print(f"User removed from role: {success}")
```

### Getting Role Members

```python
# Get all members of a role
members = auth.get_role_members('admin')
for member in members:
    print(f"Admin member: {member['user']}")
```

## Permission Checking

### Check User Permissions

```python
# Check if user has specific permission
can_manage = auth.user_has_permission('alice@example.com', 'manage_users')
print(f"Alice can manage users: {can_manage}")

# Check multiple permissions for a user
user = 'bob@example.com'
permissions = ['edit_content', 'delete_content', 'manage_users']
for perm in permissions:
    has_it = auth.user_has_permission(user, perm)
    print(f"{user} has {perm}: {has_it}")
```

### Get All User Permissions

```python
# Get all permissions for a user (inherited from all their roles)
permissions = auth.get_user_permissions('alice@example.com')
perm_names = [p['name'] for p in permissions]
print(f"Alice's permissions: {perm_names}")
```

### Permission-Based Access Control Decorator

```python
def require_permission(permission_name):
    """Decorator to check if user has permission"""
    def decorator(func):
        def wrapper(user_email, *args, **kwargs):
            if not auth.user_has_permission(user_email, permission_name):
                raise PermissionError(
                    f"User {user_email} does not have permission: {permission_name}"
                )
            return func(user_email, *args, **kwargs)
        return wrapper
    return decorator

@require_permission('delete_content')
def delete_article(user_email, article_id):
    print(f"{user_email} deleting article {article_id}")
    # Delete logic here

# Usage
try:
    delete_article('alice@example.com', 123)  # Will succeed if alice has permission
    delete_article('bob@example.com', 456)    # May fail if bob doesn't have permission
except PermissionError as e:
    print(f"Access denied: {e}")
```

## Advanced Queries

### Find Which Roles Have a Permission

```python
# Get all roles that have a specific permission
roles = auth.which_roles_can('edit_content')
role_names = [r['role'] for r in roles]
print(f"Roles that can edit content: {role_names}")
```

### Find Which Users Have a Permission

```python
# Get all users who have a specific permission
users = auth.which_users_can('manage_users')
user_list = [u['user'] for u in users]
print(f"Users who can manage users: {user_list}")
```

### Permission Matrix

```python
def get_permission_matrix(users, permissions):
    """Create a permission matrix showing which users have which permissions"""
    matrix = {}
    for user in users:
        matrix[user] = {}
        for permission in permissions:
            matrix[user][permission] = auth.user_has_permission(user, permission)
    return matrix

# Example usage
users = ['alice@example.com', 'bob@example.com', 'charlie@example.com']
permissions = ['edit_content', 'delete_content', 'manage_users']

matrix = get_permission_matrix(users, permissions)

# Print matrix
print("\nPermission Matrix:")
print(f"{'User':<25}", end='')
for perm in permissions:
    print(f"{perm:<20}", end='')
print()

for user, perms in matrix.items():
    print(f"{user:<25}", end='')
    for perm in permissions:
        has_it = '✓' if perms[perm] else '✗'
        print(f"{has_it:<20}", end='')
    print()
```

## Using the REST Client

### Basic Client Setup

```python
import uuid
from auth.client import EnhancedAuthClient

# Generate client key
client_key = str(uuid.uuid4())

# Create client
client = EnhancedAuthClient(
    api_key=client_key,
    service_url='http://localhost:5000'
)
```

### Client Operations

```python
# Create role
response = client.create_role('admin')
print(response)

# Add permission
response = client.add_permission('admin', 'manage_users')
print(response)

# Add membership
response = client.add_membership('alice@example.com', 'admin')
print(response)

# Check permission
response = client.user_has_permission('alice@example.com', 'manage_users')
if response['success'] and response['data']['has_permission']:
    print("Alice can manage users")

# Get user permissions
response = client.get_user_permissions('alice@example.com')
if response['success']:
    perms = [p['name'] for p in response['data']['permissions']]
    print(f"Alice's permissions: {perms}")
```

## Custom Database Connection

### Using PostgreSQL

```python
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from auth.services.service import AuthorizationService

# Create PostgreSQL engine
engine = create_engine('postgresql://user:pass@localhost/authdb')
SessionLocal = sessionmaker(bind=engine)

# Create session
db = SessionLocal()

# Create service
client_key = str(uuid.uuid4())
auth_service = AuthorizationService(db, client_key)

# Use the service
auth_service.add_role('admin')
auth_service.add_permission('admin', 'manage_users')

# Clean up
db.close()
```

### Using In-Memory SQLite for Testing

```python
import uuid
from auth.dal.authorization_sqlite import Authorization
from auth.models.sqlite import make_test_db_connection

# Create in-memory database
conn = make_test_db_connection()

# Create authorization instance
client_key = str(uuid.uuid4())
auth = Authorization(client_key, conn=conn)

# Use for testing
auth.add_role('test_role')
assert 'test_role' in [r['role'] for r in auth.roles]

# Clean up
conn.close()
```

## Error Handling

### Handling Common Errors

```python
import uuid
from auth import Authorization

try:
    client_key = str(uuid.uuid4())
    auth = Authorization(client_key)

    # Try to add permission to non-existent role
    result = auth.add_permission('nonexistent_role', 'some_permission')
    if not result:
        print("Failed: Role does not exist")

    # Try to remove user from role they're not in
    result = auth.del_membership('user@example.com', 'role')
    if result:  # Returns True even if user wasn't in role
        print("Operation completed (idempotent)")

except ValueError as e:
    print(f"Invalid client key: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Validating Client Keys

```python
import uuid

def is_valid_uuid4(uuid_string):
    """Check if string is a valid UUID4"""
    try:
        uuid_obj = uuid.UUID(uuid_string, version=4)
        return str(uuid_obj) == uuid_string.lower()
    except ValueError:
        return False

# Example
client_key = str(uuid.uuid4())
if is_valid_uuid4(client_key):
    auth = Authorization(client_key)
else:
    print("Invalid client key format")
```

## Real-World Examples

### Blog Platform Authorization

```python
import uuid
from auth import Authorization

# Initialize
client_key = str(uuid.uuid4())
auth = Authorization(client_key)

# Define roles
auth.add_role('author', 'Can create and edit own posts')
auth.add_role('editor', 'Can edit all posts')
auth.add_role('admin', 'Full access')

# Define permissions
author_perms = ['create_post', 'edit_own_post', 'delete_own_post', 'comment']
editor_perms = author_perms + ['edit_all_posts', 'delete_all_posts', 'moderate_comments']
admin_perms = editor_perms + ['manage_users', 'manage_roles', 'view_analytics']

for perm in author_perms:
    auth.add_permission('author', perm)

for perm in editor_perms:
    auth.add_permission('editor', perm)

for perm in admin_perms:
    auth.add_permission('admin', perm)

# Assign users
auth.add_membership('john@blog.com', 'author')
auth.add_membership('jane@blog.com', 'editor')
auth.add_membership('admin@blog.com', 'admin')

# Check permissions
def can_edit_post(user_email, post_author_email):
    """Check if user can edit a specific post"""
    # Authors can edit their own posts
    if user_email == post_author_email:
        return auth.user_has_permission(user_email, 'edit_own_post')
    # Editors can edit all posts
    return auth.user_has_permission(user_email, 'edit_all_posts')

# Usage
print(can_edit_post('john@blog.com', 'john@blog.com'))  # True (own post)
print(can_edit_post('john@blog.com', 'jane@blog.com'))  # False (not editor)
print(can_edit_post('jane@blog.com', 'john@blog.com'))  # True (editor)
```

### Multi-Tenant SaaS Application

```python
import uuid
from auth import Authorization

class TenantAuth:
    """Per-tenant authorization"""

    def __init__(self, tenant_id):
        # Each tenant gets its own client key
        self.tenant_id = tenant_id
        self.client_key = str(uuid.uuid4())  # In reality, load from database
        self.auth = Authorization(self.client_key)

    def setup_default_roles(self):
        """Set up default roles for a new tenant"""
        # Owner role
        self.auth.add_role('owner', 'Tenant owner')
        owner_perms = [
            'manage_users', 'manage_billing', 'manage_settings',
            'create_projects', 'delete_projects', 'view_analytics'
        ]
        for perm in owner_perms:
            self.auth.add_permission('owner', perm)

        # Member role
        self.auth.add_role('member', 'Regular member')
        member_perms = ['create_projects', 'view_analytics']
        for perm in member_perms:
            self.auth.add_permission('member', perm)

        # Guest role
        self.auth.add_role('guest', 'Read-only guest')
        self.auth.add_permission('guest', 'view_projects')

    def invite_user(self, email, role='member'):
        """Invite a user to the tenant"""
        return self.auth.add_membership(email, role)

    def can_user_access_feature(self, email, feature):
        """Check if user can access a feature"""
        feature_permission_map = {
            'billing': 'manage_billing',
            'analytics': 'view_analytics',
            'user_management': 'manage_users'
        }
        permission = feature_permission_map.get(feature)
        if not permission:
            return False
        return self.auth.user_has_permission(email, permission)

# Usage
tenant = TenantAuth('tenant-123')
tenant.setup_default_roles()

# Add users
tenant.invite_user('owner@company.com', 'owner')
tenant.invite_user('employee@company.com', 'member')
tenant.invite_user('contractor@external.com', 'guest')

# Check access
print(tenant.can_user_access_feature('owner@company.com', 'billing'))  # True
print(tenant.can_user_access_feature('employee@company.com', 'billing'))  # False
print(tenant.can_user_access_feature('contractor@external.com', 'analytics'))  # False
```

### E-commerce Platform

```python
import uuid
from auth import Authorization

client_key = str(uuid.uuid4())
auth = Authorization(client_key)

# Set up roles
auth.add_role('customer', 'Regular customer')
auth.add_role('vendor', 'Product vendor')
auth.add_role('support', 'Customer support')
auth.add_role('admin', 'Platform administrator')

# Customer permissions
customer_perms = ['browse_products', 'purchase', 'review', 'track_orders']
for perm in customer_perms:
    auth.add_permission('customer', perm)

# Vendor permissions (includes customer permissions)
vendor_perms = customer_perms + [
    'add_products', 'edit_own_products', 'view_sales',
    'manage_inventory', 'respond_to_reviews'
]
for perm in vendor_perms:
    auth.add_permission('vendor', perm)

# Support permissions
support_perms = ['view_orders', 'view_customer_info', 'issue_refunds', 'send_messages']
for perm in support_perms:
    auth.add_permission('support', perm)

# Admin permissions
admin_perms = vendor_perms + support_perms + [
    'manage_users', 'manage_vendors', 'view_analytics',
    'manage_platform_settings'
]
for perm in admin_perms:
    auth.add_permission('admin', perm)

# Helper functions
def can_modify_product(user_email, product_vendor_email):
    """Check if user can modify a product"""
    # Vendors can edit their own products
    if user_email == product_vendor_email:
        return auth.user_has_permission(user_email, 'edit_own_products')
    # Admins can edit any product
    return auth.user_has_permission(user_email, 'manage_platform_settings')

def get_user_dashboard_permissions(user_email):
    """Get dashboard sections user can access"""
    sections = {
        'sales': 'view_sales',
        'products': 'add_products',
        'customers': 'view_customer_info',
        'analytics': 'view_analytics',
        'settings': 'manage_platform_settings'
    }

    accessible = {}
    for section, permission in sections.items():
        accessible[section] = auth.user_has_permission(user_email, permission)

    return accessible

# Usage
auth.add_membership('customer@email.com', 'customer')
auth.add_membership('vendor@shop.com', 'vendor')
auth.add_membership('support@platform.com', 'support')
auth.add_membership('admin@platform.com', 'admin')

# Check permissions
print(can_modify_product('vendor@shop.com', 'vendor@shop.com'))  # True
print(can_modify_product('vendor@shop.com', 'other@shop.com'))   # False
print(can_modify_product('admin@platform.com', 'vendor@shop.com'))  # True

# Get dashboard access
vendor_access = get_user_dashboard_permissions('vendor@shop.com')
print(f"Vendor dashboard access: {vendor_access}")
```

## Best Practices

1. **Always use UUID4 for client keys**
   ```python
   client_key = str(uuid.uuid4())  # Correct
   ```

2. **Check operation results**
   ```python
   success = auth.add_role('new_role')
   if success:
       # Role created successfully
       auth.add_permission('new_role', 'some_permission')
   ```

3. **Use descriptive role and permission names**
   ```python
   # Good
   auth.add_role('content_moderator', 'Moderates user-generated content')
   auth.add_permission('content_moderator', 'review_flagged_content')

   # Avoid
   auth.add_role('role1')
   auth.add_permission('role1', 'perm1')
   ```

4. **Implement least privilege principle**
   ```python
   # Grant only necessary permissions
   auth.add_role('api_reader', 'Read-only API access')
   auth.add_permission('api_reader', 'read_data')
   # Don't add write permissions unless needed
   ```

5. **Clean up when deleting users**
   ```python
   def remove_user(email):
       # Get user's roles
       user_roles = auth.get_user_roles(email)
       # Remove from all roles
       for role_info in user_roles:
           auth.del_membership(email, role_info['role'])
   ```

## Testing

```python
import unittest
import uuid
from auth.dal.authorization_sqlite import Authorization
from auth.models.sqlite import make_test_db_connection

class TestAuthorization(unittest.TestCase):
    def setUp(self):
        """Set up test database"""
        self.conn = make_test_db_connection()
        self.client_key = str(uuid.uuid4())
        self.auth = Authorization(self.client_key, conn=self.conn)

    def tearDown(self):
        """Clean up"""
        self.conn.close()

    def test_role_creation(self):
        """Test creating a role"""
        result = self.auth.add_role('test_role')
        self.assertTrue(result)

        roles = [r['role'] for r in self.auth.roles]
        self.assertIn('test_role', roles)

    def test_permission_check(self):
        """Test permission checking"""
        self.auth.add_role('admin')
        self.auth.add_permission('admin', 'manage_users')
        self.auth.add_membership('user@test.com', 'admin')

        has_perm = self.auth.user_has_permission('user@test.com', 'manage_users')
        self.assertTrue(has_perm)

if __name__ == '__main__':
    unittest.main()
```
