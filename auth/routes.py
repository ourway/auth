"""
FastAPI routes for authorization service
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from auth.database import get_db
from auth.schemas import (
    BooleanResponse,
    MembersResponse,
    PermissionsResponse,
    RolesResponse,
    WhichRolesCanResponse,
    WhichUsersCanResponse,
)
from auth.service import AuthorizationService

router = APIRouter()


def get_auth_service(client: str, db: Session = Depends(get_db)):
    """Dependency to get authorization service"""
    return AuthorizationService(db, client, validate_client=True)


@router.get("/ping", response_model=dict)
async def ping():
    """Health check endpoint"""
    return {"message": "PONG"}


@router.get("/api/membership/{client}/{user}/{group}", response_model=BooleanResponse)
async def check_membership(
    client: str,
    user: str,
    group: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Check if user is member of a group"""
    result = auth_service.has_membership(user, group)
    return BooleanResponse(result=result)


@router.post("/api/membership/{client}/{user}/{group}", response_model=BooleanResponse)
async def add_membership(
    client: str,
    user: str,
    group: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Add user to a group"""
    result = auth_service.add_membership(user, group)
    return BooleanResponse(result=result)


@router.delete(
    "/api/membership/{client}/{user}/{group}", response_model=BooleanResponse
)
async def remove_membership(
    client: str,
    user: str,
    group: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Remove user from a group"""
    result = auth_service.del_membership(user, group)
    return BooleanResponse(result=result)


@router.get("/api/permission/{client}/{group}/{name}", response_model=BooleanResponse)
async def check_permission(
    client: str,
    group: str,
    name: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Check if group has permission"""
    result = auth_service.has_permission(group, name)
    return BooleanResponse(result=result)


@router.post("/api/permission/{client}/{group}/{name}", response_model=BooleanResponse)
async def add_permission(
    client: str,
    group: str,
    name: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Add permission to a group"""
    result = auth_service.add_permission(group, name)
    return BooleanResponse(result=result)


@router.delete(
    "/api/permission/{client}/{group}/{name}", response_model=BooleanResponse
)
async def remove_permission(
    client: str,
    group: str,
    name: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Remove permission from a group"""
    result = auth_service.del_permission(group, name)
    return BooleanResponse(result=result)


@router.get(
    "/api/has_permission/{client}/{user}/{name}", response_model=BooleanResponse
)
async def check_user_permission(
    client: str,
    user: str,
    name: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Check if user has permission"""
    result = auth_service.user_has_permission(user, name)
    return BooleanResponse(result=result)


@router.get("/api/user_permissions/{client}/{user}", response_model=PermissionsResponse)
async def get_user_permissions(
    client: str,
    user: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Get all permissions for a user"""
    permissions = auth_service.get_user_permissions(user)
    # Convert dict entries to PermissionResponse objects
    from auth.schemas import PermissionResponse

    permission_responses = [PermissionResponse(**perm) for perm in permissions]
    return PermissionsResponse(results=permission_responses)


@router.get("/api/role_permissions/{client}/{role}", response_model=PermissionsResponse)
async def get_role_permissions(
    client: str,
    role: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Get all permissions for a role"""
    permissions = auth_service.get_permissions(role)
    # Convert dict entries to PermissionResponse objects
    from auth.schemas import PermissionResponse

    permission_responses = [PermissionResponse(**perm) for perm in permissions]
    return PermissionsResponse(results=permission_responses)


@router.get("/api/user_roles/{client}/{user}", response_model=MembersResponse)
async def get_user_roles(
    client: str,
    user: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Get all roles for a user"""
    roles = auth_service.get_user_roles(user)
    # Convert dict entries to MembershipResponse objects
    from auth.schemas import MembershipResponse

    role_responses = [MembershipResponse(**role) for role in roles]
    return MembersResponse(result=role_responses)


@router.get("/api/members/{client}/{role}", response_model=MembersResponse)
async def get_role_members(
    client: str,
    role: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Get all members of a role"""
    members = auth_service.get_role_members(role)
    # Convert dict entries to MembershipResponse objects
    from auth.schemas import MembershipResponse

    member_responses = [MembershipResponse(**member) for member in members]
    return MembersResponse(result=member_responses)


@router.get("/api/roles/{client}", response_model=RolesResponse)
async def list_roles(
    client: str, auth_service: AuthorizationService = Depends(get_auth_service)
):
    """List all roles"""
    roles = auth_service.get_roles()
    # Convert dict entries to RoleResponse objects
    from auth.schemas import RoleResponse

    role_responses = [RoleResponse(**role) for role in roles]
    return RolesResponse(result=role_responses)


@router.get(
    "/api/which_roles_can/{client}/{name}", response_model=WhichRolesCanResponse
)
async def which_roles_can(
    client: str,
    name: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Get roles that can perform an action"""
    roles = auth_service.which_roles_can(name)
    # Convert dict entries to RoleResponse objects
    from auth.schemas import RoleResponse

    role_responses = [RoleResponse(**role) for role in roles]
    return WhichRolesCanResponse(result=role_responses)


@router.get(
    "/api/which_users_can/{client}/{name}", response_model=WhichUsersCanResponse
)
async def which_users_can(
    client: str,
    name: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Get users that can perform an action"""
    users = auth_service.which_users_can(name)
    # Convert dict entries to MembershipResponse objects
    from auth.schemas import MembershipResponse

    user_responses = [MembershipResponse(**user) for user in users]
    return WhichUsersCanResponse(result=user_responses)


@router.post("/api/role/{client}/{role}", response_model=BooleanResponse)
async def create_role(
    client: str,
    role: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Create a new role"""
    result = auth_service.add_role(role)
    return BooleanResponse(result=result)


@router.delete("/api/role/{client}/{role}", response_model=BooleanResponse)
async def delete_role(
    client: str,
    role: str,
    auth_service: AuthorizationService = Depends(get_auth_service),
):
    """Delete a role"""
    result = auth_service.del_role(role)
    return BooleanResponse(result=result)
