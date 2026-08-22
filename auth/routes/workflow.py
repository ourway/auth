"""Workflow routes: which users may run a named workflow."""

import logging

from auth.audit import (
    AuditAction,
)
from auth.decorators import audit_log
from auth.response_format import (
    APIResponse,
    format_permission_response,
    format_role_members_response,
)
from auth.routes._common import (
    _get_auth_service,
    _strict_reason,
    with_db_session,
)
from auth.sanitizer import sanitize_input
from auth.validation import (
    validate_permission_name,
    validate_user_role_combination,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the workflow routes on ``app``."""

    # Workflow-related endpoints
    @app.route("/api/workflow/users/<workflow_name>", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.LIST_MEMBERSHIPS,
        resource_extractor=lambda kwargs: f"workflow:{kwargs['workflow_name']}",
    )
    @sanitize_input
    def get_users_for_workflow(db, workflow_name):
        """Get all users who can run a specific workflow"""
        # Validate workflow name
        if not validate_permission_name(workflow_name):
            return APIResponse.bad_request(f"Invalid workflow name: {workflow_name}")

        auth_service = _get_auth_service(db)

        users = auth_service.which_users_can(workflow_name)

        return APIResponse.success(
            data=format_role_members_response(users),
            message=f"Retrieved users who can run workflow '{workflow_name}'",
        )

    @app.route("/api/workflow/user/<user>/can_run/<workflow_name>", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.CHECK_PERMISSION,
        resource_extractor=lambda kwargs: f"workflow:{kwargs['workflow_name']}",
    )
    @sanitize_input
    def check_user_workflow_permission(db, user, workflow_name):
        """Check if a user can run a specific workflow"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, workflow_name)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        auth_service = _get_auth_service(db)

        result = auth_service.user_has_permission(user, workflow_name)
        data = format_permission_response(result)
        if not result:
            reason = _strict_reason(auth_service, user)
            if reason:
                data["reason"] = reason

        return APIResponse.success(
            data=data,
            message=f"Workflow permission check for user '{user}' and workflow '{workflow_name}' completed",
        )
