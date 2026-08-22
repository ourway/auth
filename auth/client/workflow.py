"""Workflow permission helpers."""

from typing import Any, Dict

from auth.client.keys import ApiKeyMixin


class WorkflowMixin(ApiKeyMixin):
    """Workflow-scoped permission questions."""

    # Workflow-related methods
    def get_users_for_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """Get all users who can run a specific workflow.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["workflow_users"].format(workflow_name=workflow_name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"workflow_name": workflow_name})

    def check_user_workflow_permission(
        self, user: str, workflow_name: str
    ) -> Dict[str, Any]:
        """Check if a user can run a specific workflow.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["workflow_permission"].format(
            user=user, workflow_name=workflow_name
        )
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(
                e, data={"user": user, "workflow_name": workflow_name}
            )
