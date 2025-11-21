#!/bin/bash

# Auth Service API Showcase
# This script demonstrates the capabilities of the Auth service running on port 4000

set -e  # Exit on any error

echo "========================================="
echo "Auth Service API Showcase"
echo "========================================="
echo

# Configuration
SERVER_URL="http://localhost:4000"
CLIENT_KEY="$(uuidgen)"
echo "Using client key: $CLIENT_KEY"
echo

# Function to make API requests with error handling
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_status=${4:-200}
    
    echo "  $method $endpoint"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -o response.json -w "%{http_code}" -X GET -H "Authorization: Bearer $CLIENT_KEY" "$SERVER_URL$endpoint")
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -o response.json -w "%{http_code}" -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $CLIENT_KEY" -d "$data" "$SERVER_URL$endpoint")
    elif [ "$method" = "DELETE" ]; then
        response=$(curl -s -o response.json -w "%{http_code}" -X DELETE -H "Authorization: Bearer $CLIENT_KEY" "$SERVER_URL$endpoint")
    else
        echo "  ERROR: Unsupported method $method"
        return 1
    fi
    
    status_code="${response: -3}"
    
    if [ "$status_code" = "$expected_status" ]; then
        echo "  ✓ Status: $status_code (Expected: $expected_status)"
        if [ -s response.json ]; then
            echo "  Response: $(cat response.json | head -c 200)..."
        fi
        echo
        return 0
    else
        echo "  ✗ Status: $status_code (Expected: $expected_status)"
        if [ -s response.json ]; then
            echo "  Response: $(cat response.json)"
        fi
        echo
        return 1
    fi
}

# Check if server is running
echo "1. Checking if server is running..."
make_request GET "/ping" "" 200

echo "2. Creating roles..."
make_request POST "/api/role/admin" '{}' 200
make_request POST "/api/role/editor" '{}' 200
make_request POST "/api/role/viewer" '{}' 200

echo "3. Adding permissions to roles..."
make_request POST "/api/permission/admin/write" '{}' 200
make_request POST "/api/permission/admin/read" '{}' 200
make_request POST "/api/permission/editor/write" '{}' 200
make_request POST "/api/permission/viewer/read" '{}' 200

echo "4. Creating user memberships..."
make_request POST "/api/membership/john/admin" '{}' 200
make_request POST "/api/membership/jane/editor" '{}' 200
make_request POST "/api/membership/bob/viewer" '{}' 200

echo "5. Checking user permissions..."
make_request GET "/api/has_permission/john/write" "" 200
make_request GET "/api/has_permission/jane/write" "" 200
make_request GET "/api/has_permission/bob/write" "" 200

echo "6. Getting user permissions..."
make_request GET "/api/user_permissions/john" "" 200
make_request GET "/api/user_permissions/jane" "" 200

echo "7. Getting user roles..."
make_request GET "/api/user_roles/john" "" 200
make_request GET "/api/user_roles/jane" "" 200

echo "8. Getting role permissions..."
make_request GET "/api/role_permissions/admin" "" 200
make_request GET "/api/role_permissions/editor" "" 200

echo "9. Getting role members..."
make_request GET "/api/members/admin" "" 200
make_request GET "/api/members/editor" "" 200

echo "10. Listing all roles..."
make_request GET "/api/roles" "" 200

echo "11. Finding which roles can perform actions..."
make_request GET "/api/which_roles_can/write" "" 200
make_request GET "/api/which_roles_can/read" "" 200

echo "12. Finding which users can perform actions..."
make_request GET "/api/which_users_can/write" "" 200
make_request GET "/api/which_users_can/read" "" 200

echo "13. Testing permission removal..."
make_request DELETE "/api/permission/editor/write" "" 200

echo "14. Testing membership removal..."
make_request DELETE "/api/membership/jane/editor" "" 200
# Re-add for demonstration purposes
make_request POST "/api/membership/jane/editor" '{}' 200

echo "15. Testing role removal..."
make_request DELETE "/api/role/viewer" "" 200

echo "========================================="
echo "API Showcase Completed Successfully!"
echo "========================================="
echo
echo "Summary of operations performed:"
echo "- Role management (create, delete)"
echo "- Permission assignment (add, remove)"
echo "- User membership management"
echo "- Permission checking for users"
echo "- Permission and role listing"
echo "- Cross-referencing (which roles can, which users can)"
echo

# Cleanup temporary file
rm -f response.json

# Provide summary of the API operations tested
echo "API Operations Tested:"
echo "  GET    /ping"
echo "  GET    /api/roles"
echo "  POST   /api/role/{role}"
echo "  DELETE /api/role/{role}"
echo "  GET    /api/has_permission/{user}/{name}"
echo "  GET    /api/user_permissions/{user}"
echo "  GET    /api/user_roles/{user}"
echo "  GET    /api/role_permissions/{role}"
echo "  GET    /api/members/{role}"
echo "  GET    /api/which_roles_can/{name}"
echo "  GET    /api/which_users_can/{name}"
echo "  POST   /api/permission/{role}/{name}"
echo "  DELETE /api/permission/{role}/{name}"
echo "  POST   /api/membership/{user}/{role}"
echo "  DELETE /api/membership/{user}/{role}"
