"""
APScheduler integration for workflow permission checking
"""

import atexit
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from auth.services.service import AuthorizationService


class WorkflowPermissionChecker:
    """Handles workflow permission checking for APScheduler integration"""

    def __init__(self, auth_service: AuthorizationService):
        self.auth_service = auth_service
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

        # Shut down the scheduler when exiting the app
        # Suppress any logging errors during shutdown
        def safe_shutdown():
            try:
                # Disable scheduler logging before shutdown to prevent errors
                # when logging system is already closed
                self.scheduler._logger.disabled = True
                self.scheduler.shutdown(wait=False)
            except Exception:
                pass  # Ignore errors during shutdown (e.g., closed logging)
        atexit.register(safe_shutdown)

    def get_users_with_workflow_permission(
        self, workflow_name: str
    ) -> List[Dict[str, Any]]:
        """
        Get all users who have permission to run a specific workflow
        """
        try:
            # In our current structure, which_users_can returns members with user/role format
            users_with_permission = self.auth_service.which_users_can(workflow_name)

            # Extract unique users from the results
            unique_users = set()
            result = []

            for item in users_with_permission:
                user = item.get("user")
                if user and user not in unique_users:
                    unique_users.add(user)
                    result.append(
                        {"user": user, "workflow": workflow_name, "can_run": True}
                    )

            return result
        except Exception as e:
            print(f"Error checking workflow permissions: {e}")
            return []

    def schedule_periodic_permission_check(
        self, workflow_name: str, callback_func, cron_expression: str = "*/5 * * * *"
    ):
        """
        Schedule a periodic check for users who can run a specific workflow
        """

        def job():
            users = self.get_users_with_workflow_permission(workflow_name)
            callback_func(users)

        self.scheduler.add_job(
            func=job,
            trigger=CronTrigger.from_crontab(cron_expression),
            id=f"workflow_check_{workflow_name}",
            name=f"Check permissions for workflow {workflow_name}",
            replace_existing=True,
        )

    def add_workflow_permission_check_job(
        self, workflow_name: str, callback_func, interval_seconds: int = 300
    ):
        """
        Add a job that periodically checks workflow permissions
        """

        def job():
            try:
                users = self.get_users_with_workflow_permission(workflow_name)
                callback_func(users)
            except Exception as e:
                print(f"Error in workflow permission check job: {e}")

        self.scheduler.add_job(
            func=job,
            trigger="interval",
            seconds=interval_seconds,
            id=f"workflow_check_interval_{workflow_name}",
            name=f"Interval check for workflow {workflow_name}",
            replace_existing=True,
        )

    def get_workflows_for_user(self, user: str) -> List[str]:
        """
        Get all workflows that a user has permission to run
        """
        try:
            permissions = self.auth_service.get_user_permissions(user)
            workflow_names: List[str] = [
                str(perm.get("name")) for perm in permissions if perm.get("name")
            ]
            return workflow_names
        except Exception as e:
            print(f"Error getting workflows for user: {e}")
            return []

    def can_user_run_workflow(self, user: str, workflow_name: str) -> bool:
        """
        Check if a specific user can run a specific workflow
        """
        try:
            return self.auth_service.user_has_permission(user, workflow_name)
        except Exception as e:
            print(f"Error checking user workflow permission: {e}")
            return False


# Global workflow permission checker instance
workflow_checker = None


def initialize_workflow_checker(auth_service: Optional[AuthorizationService] = None):
    """
    Initialize the workflow permission checker

    Note: If no auth_service is provided, we create a temporary one for initialization.
    The WorkflowPermissionChecker will use the auth_service's database session,
    so no connection leak occurs.
    """
    global workflow_checker
    if auth_service is None:
        # Create a temporary database session for initialization
        # This will be closed after the auth_service is created
        from auth.database import get_db
        with get_db() as db:
            auth_service = AuthorizationService(
                db, "workflow_checker", validate_client=False
            )
            workflow_checker = WorkflowPermissionChecker(auth_service)
    else:
        workflow_checker = WorkflowPermissionChecker(auth_service)


def get_workflow_checker() -> Optional[WorkflowPermissionChecker]:
    """
    Get the global workflow permission checker instance
    """
    return workflow_checker


def get_users_for_workflow(workflow_name: str) -> List[Dict[str, Any]]:
    """
    Convenience function to get users who can run a workflow
    """
    if workflow_checker:
        return workflow_checker.get_users_with_workflow_permission(workflow_name)
    return []


def can_user_run_workflow(user: str, workflow_name: str) -> bool:
    """
    Convenience function to check if user can run workflow
    """
    if workflow_checker:
        return workflow_checker.can_user_run_workflow(user, workflow_name)
    return False


def get_workflows_for_user(user: str) -> List[str]:
    """
    Convenience function to get workflows for a user
    """
    if workflow_checker:
        return workflow_checker.get_workflows_for_user(user)
    return []
