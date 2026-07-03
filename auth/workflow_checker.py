"""
APScheduler integration for workflow permission checking
"""

import atexit
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from auth.services.service import AuthorizationService


class WorkflowPermissionChecker:
    """Handles workflow permission checking for APScheduler integration"""

    def __init__(
        self,
        auth_service: Optional[AuthorizationService] = None,
        client: str = "workflow_checker",
    ):
        # When no service is supplied, each operation opens its own session
        # via _service(); a long-lived service would otherwise hold a session
        # that get_db() has already closed.
        self.auth_service = auth_service
        self.client = auth_service.client if auth_service is not None else client
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

    @contextmanager
    def _service(self):
        """Yield an AuthorizationService backed by a live database session."""
        if self.auth_service is not None:
            yield self.auth_service
        else:
            from auth.database import get_db

            with get_db() as db:
                yield AuthorizationService(db, self.client, validate_client=False)

    def get_users_with_workflow_permission(
        self, workflow_name: str
    ) -> List[Dict[str, Any]]:
        """
        Get all users who have permission to run a specific workflow
        """
        try:
            # In our current structure, which_users_can returns members with user/role format
            with self._service() as svc:
                users_with_permission = svc.which_users_can(workflow_name)

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
            with self._service() as svc:
                permissions = svc.get_user_permissions(user)
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
            with self._service() as svc:
                return bool(svc.user_has_permission(user, workflow_name))
        except Exception as e:
            print(f"Error checking user workflow permission: {e}")
            return False


# Global workflow permission checker instance
workflow_checker = None


def initialize_workflow_checker(auth_service: Optional[AuthorizationService] = None):
    """
    Initialize the workflow permission checker

    Without an explicit auth_service the checker opens a fresh database
    session per operation. Re-initialization without arguments is a no-op so
    repeated create_app() calls don't leak scheduler threads.
    """
    global workflow_checker
    if auth_service is None:
        if workflow_checker is None:
            workflow_checker = WorkflowPermissionChecker()
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
