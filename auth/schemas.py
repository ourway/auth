"""
Pydantic models for FastAPI request/response schemas
"""

from pydantic import BaseModel, ConfigDict
from typing import List, Optional


class RoleCreate(BaseModel):
    role: str
    description: Optional[str] = None


class RoleResponse(BaseModel):
    role: str
    description: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)


class PermissionCreate(BaseModel):
    name: str


class PermissionResponse(BaseModel):
    name: str
    
    model_config = ConfigDict(from_attributes=True)


class MembershipCreate(BaseModel):
    user: str
    role: str


class MembershipResponse(BaseModel):
    user: str
    role: str
    
    model_config = ConfigDict(from_attributes=True)


class UserPermissionCheck(BaseModel):
    user: str
    name: str


class PermissionCheck(BaseModel):
    role: str
    name: str


class BooleanResponse(BaseModel):
    result: bool


class RolesResponse(BaseModel):
    result: List[RoleResponse]


class PermissionsResponse(BaseModel):
    results: List[PermissionResponse]


class MembersResponse(BaseModel):
    result: List[MembershipResponse]


class WhichRolesCanResponse(BaseModel):
    result: List[RoleResponse]


class WhichUsersCanResponse(BaseModel):
    result: List[MembershipResponse]