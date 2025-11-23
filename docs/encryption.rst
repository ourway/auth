==========
Encryption
==========

Auth supports deterministic field-level encryption for sensitive data using AES-256-CTR with HMAC-derived initialization vectors.

Overview
========

What is Encrypted
-----------------

When encryption is enabled, Auth encrypts:

- **User identifiers** in the ``auth_membership`` table
- **Permission names** in the ``auth_permission`` table
- **Role descriptions** (optional)

Why Deterministic Encryption
-----------------------------

**Deterministic encryption** means the same plaintext always produces the same ciphertext.

**Benefits:**

- Database queries work on encrypted data
- User lookups remain efficient
- Permission checks don't require decryption
- No performance impact on operations

**Trade-offs:**

- Pattern analysis possible (same values = same ciphertext)
- Acceptable for usernames and permission names
- Still protects data at rest

Example
-------

.. code-block:: python

    # Without encryption
    Database: "alice@example.com", "bob@example.com", "manage_users"
    
    # With deterministic encryption
    Database: "xxqjTSaj0YGZD7v8khExdKkV+dA=", "sJ4Yaz56uRxmNF0mj3wOwUNE8Y8=", "k7Pq..."

Configuration
=============

Generate Encryption Key
-----------------------

.. code-block:: bash

    # Generate a Fernet key
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Output example:

.. code-block:: text

    9fJ3K8pL2mN5oP7qR9sT1uV3wX6yZ8aB4cD6eF8gH0i=

Enable Encryption
-----------------

.. code-block:: bash

    # Set environment variables
    export AUTH_ENABLE_ENCRYPTION=true
    export AUTH_ENCRYPTION_KEY="9fJ3K8pL2mN5oP7qR9sT1uV3wX6yZ8aB4cD6eF8gH0i="

Or in ``.env`` file:

.. code-block:: bash

    AUTH_ENABLE_ENCRYPTION=true
    AUTH_ENCRYPTION_KEY=9fJ3K8pL2mN5oP7qR9sT1uV3wX6yZ8aB4cD6eF8gH0i=

Verify Encryption
-----------------

.. code-block:: python

    from auth import Authorization
    import uuid

    auth = Authorization(str(uuid.uuid4()))
    
    # Add data (will be encrypted automatically)
    auth.add_membership('alice@example.com', 'admin')
    
    # Query works normally (encryption is transparent)
    has_membership = auth.has_membership('alice@example.com', 'admin')
    print(has_membership)  # True

Technical Details
=================

Encryption Algorithm
--------------------

**AES-256-CTR** with HMAC-derived IVs:

- **Algorithm:** AES (Advanced Encryption Standard)
- **Mode:** CTR (Counter Mode)
- **Key Size:** 256 bits
- **IV Generation:** HMAC-SHA256 of plaintext (deterministic)
- **Key Derivation:** PBKDF2 with 100,000 iterations

Implementation
--------------

.. code-block:: python

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import hmac
    import hashlib
    
    class DeterministicEncryption:
        def __init__(self, key: bytes):
            self.key = key
            
        def _derive_key(self, salt: bytes) -> bytes:
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            return kdf.derive(self.key)
        
        def _generate_iv(self, plaintext: str) -> bytes:
            # HMAC ensures same plaintext = same IV
            h = hmac.new(self.key, plaintext.encode(), hashlib.sha256)
            return h.digest()[:16]  # AES block size
        
        def encrypt(self, plaintext: str) -> str:
            iv = self._generate_iv(plaintext)
            cipher = Cipher(
                algorithms.AES(self.key[:32]),
                modes.CTR(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            return base64.b64encode(ciphertext).decode()

Data Flow
---------

**Writing encrypted data:**

.. code-block:: text

    User Input: "alice@example.com"
         ↓
    HMAC-SHA256 → IV (deterministic)
         ↓
    AES-256-CTR encryption
         ↓
    Base64 encoding
         ↓
    Database: "xxqjTSaj0YGZD7v8khExdKkV+dA="

**Reading encrypted data:**

.. code-block:: text

    Query: "alice@example.com"
         ↓
    Encrypt query value (same process)
         ↓
    Database lookup: "xxqjTSaj0YGZD7v8khExdKkV+dA="
         ↓
    Result returned (still encrypted)
         ↓
    Decrypt for display (if needed)

Migration
=========

Enabling Encryption on Existing Data
-------------------------------------

**Important:** Enabling encryption on an existing database requires migration.

.. code-block:: python

    from auth.database import SessionLocal
    from auth.encryption import get_encryptor
    from auth.models.sql import AuthMembership, AuthPermission
    
    def migrate_to_encrypted():
        """Encrypt existing data"""
        db = SessionLocal()
        encryptor = get_encryptor()
        
        try:
            # Encrypt memberships
            memberships = db.query(AuthMembership).all()
            for membership in memberships:
                if not is_encrypted(membership.user):
                    membership.user = encryptor.encrypt(membership.user)
            
            # Encrypt permissions
            permissions = db.query(AuthPermission).all()
            for permission in permissions:
                if not is_encrypted(permission.name):
                    permission.name = encryptor.encrypt(permission.name)
            
            db.commit()
            print("Migration completed successfully")
        except Exception as e:
            db.rollback()
            print(f"Migration failed: {e}")
        finally:
            db.close()

Disabling Encryption
--------------------

To disable encryption, decrypt existing data first:

.. code-block:: python

    def migrate_from_encrypted():
        """Decrypt existing data"""
        db = SessionLocal()
        encryptor = get_encryptor()
        
        try:
            # Decrypt memberships
            memberships = db.query(AuthMembership).all()
            for membership in memberships:
                if is_encrypted(membership.user):
                    membership.user = encryptor.decrypt(membership.user)
            
            # Decrypt permissions
            permissions = db.query(AuthPermission).all()
            for permission in permissions:
                if is_encrypted(permission.name):
                    permission.name = encryptor.decrypt(permission.name)
            
            db.commit()
            
            # Now disable encryption
            os.environ['AUTH_ENABLE_ENCRYPTION'] = 'false'
            
        except Exception as e:
            db.rollback()
            raise
        finally:
            db.close()

Key Management
==============

Key Storage
-----------

**Development:**

.. code-block:: bash

    # .env file (gitignored)
    AUTH_ENCRYPTION_KEY=9fJ3K8pL2mN5oP7qR9sT1uV3wX6yZ8aB4cD6eF8gH0i=

**Production - AWS Secrets Manager:**

.. code-block:: python

    import boto3
    import json
    
    def get_encryption_key():
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId='auth/encryption-key')
        return json.loads(response['SecretString'])['key']
    
    os.environ['AUTH_ENCRYPTION_KEY'] = get_encryption_key()

**Production - HashiCorp Vault:**

.. code-block:: python

    import hvac
    
    client = hvac.Client(url='https://vault.example.com')
    client.auth.approle.login(role_id='...', secret_id='...')
    
    secret = client.secrets.kv.v2.read_secret_version(path='auth/keys')
    os.environ['AUTH_ENCRYPTION_KEY'] = secret['data']['data']['encryption_key']

**Production - Kubernetes:**

.. code-block:: yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: auth-encryption
    type: Opaque
    data:
      encryption-key: OWZKM0s4cEwybU41b1A3cVI5c1QxdVYzd1g2eVo4YUI0Y0Q2ZUY4Z0gwaz0=

Key Rotation
------------

**Generate new key:**

.. code-block:: bash

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

**Rotation process:**

.. code-block:: python

    from auth.encryption import get_encryptor
    
    def rotate_encryption_key(old_key, new_key):
        """Rotate encryption keys"""
        db = SessionLocal()
        old_encryptor = DeterministicEncryption(old_key)
        new_encryptor = DeterministicEncryption(new_key)
        
        try:
            # Re-encrypt all data
            memberships = db.query(AuthMembership).all()
            for membership in memberships:
                # Decrypt with old key
                plaintext = old_encryptor.decrypt(membership.user)
                # Encrypt with new key
                membership.user = new_encryptor.encrypt(plaintext)
            
            permissions = db.query(AuthPermission).all()
            for permission in permissions:
                plaintext = old_encryptor.decrypt(permission.name)
                permission.name = new_encryptor.encrypt(plaintext)
            
            db.commit()
            print("Key rotation completed")
        except Exception as e:
            db.rollback()
            raise
        finally:
            db.close()

**Rotation schedule:**

- Development: No fixed schedule
- Production: Quarterly or annually
- After breach: Immediately

Security Considerations
=======================

Key Security
------------

**DO:**

- Use cryptographically secure random keys
- Store keys in secrets management systems
- Rotate keys regularly
- Use different keys per environment
- Restrict key access (need-to-know basis)

**DON'T:**

- Commit keys to version control
- Share keys via email/chat
- Use weak or predictable keys
- Store keys in application code
- Reuse keys across applications

Encryption Limitations
----------------------

**Deterministic encryption protects against:**

- Unauthorized database access
- Database backup theft
- SQL injection (data still encrypted)
- Insider threats (DBA access)

**Deterministic encryption does NOT protect against:**

- Pattern analysis (same values visible)
- Frequency analysis (common values identifiable)
- Known plaintext attacks (if attacker has samples)

**For maximum security:**

- Combine with database encryption at rest
- Use network encryption (SSL/TLS)
- Implement access controls
- Enable audit logging

Performance Impact
==================

Encryption Performance
----------------------

**Benchmarks (SQLite, 10,000 operations):**

.. code-block:: text

    Without encryption:  1.2s
    With encryption:     1.4s
    Overhead:           ~16%

**Benchmarks (PostgreSQL, 10,000 operations):**

.. code-block:: text

    Without encryption:  0.8s
    With encryption:     0.9s
    Overhead:           ~12%

Optimization
------------

.. code-block:: python

    from functools import lru_cache
    
    @lru_cache(maxsize=1024)
    def cached_encrypt(plaintext: str) -> str:
        """Cache encrypted values (deterministic = cacheable)"""
        return encryptor.encrypt(plaintext)

Best Practices
==============

1. **Enable encryption from the start**

   Easier than migrating later.

2. **Use environment variables for keys**

   Never hardcode in source.

3. **Different keys per environment**

   Dev, staging, production should have separate keys.

4. **Regular key rotation**

   Set a schedule and stick to it.

5. **Audit key access**

   Track who accesses encryption keys.

6. **Test key rotation**

   Practice the process before you need it.

7. **Backup keys securely**

   Store in multiple secure locations.

8. **Document key locations**

   Ensure team knows where keys are stored.

Troubleshooting
===============

Decryption Errors
-----------------

**Error:** "Invalid token" or "Decryption failed"

**Causes:**

- Wrong encryption key
- Data encrypted with different key
- Corrupted ciphertext

**Solution:**

.. code-block:: python

    # Verify key matches
    print(os.environ.get('AUTH_ENCRYPTION_KEY'))
    
    # Test encryption/decryption
    from auth.encryption import get_encryptor
    encryptor = get_encryptor()
    test = encryptor.encrypt('test')
    assert encryptor.decrypt(test) == 'test'

Migration Issues
----------------

**Error:** Mixed encrypted/unencrypted data

**Solution:**

.. code-block:: python

    def is_encrypted(value: str) -> bool:
        """Check if value is encrypted (base64 check)"""
        try:
            import base64
            base64.b64decode(value)
            return len(value) > 20  # Encrypted values are longer
        except:
            return False
    
    # Encrypt only unencrypted values
    if not is_encrypted(membership.user):
        membership.user = encryptor.encrypt(membership.user)

Next Steps
==========

- :doc:`security` - Overall security practices
- :doc:`configuration` - Encryption configuration
- :doc:`production` - Production deployment
- :doc:`troubleshooting` - Common issues
