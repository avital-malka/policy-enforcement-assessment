import json

from log_config import logging
from decorators import validate_json_fields, log_function_calls
from policy_manager import PolicyManager

logger = logging.getLogger(__name__)


class PolicyAPI:
    def __init__(self) -> None:
        self.policy_manager = PolicyManager()

    @validate_json_fields(expected_fields=["name", "description"])
    @log_function_calls(logger=logger)
    def create_policy(self, json_input: str) -> str:
        """
        Create a new policy using the provided JSON input.

        Args:
            json_input (str): JSON input containing policy details.

        Returns:
            str: JSON response with the ID of the created policy.

        Raises:
            ValueError: If the JSON input is not in the expected format.
        """
        data = json.loads(json_input)
        policy = self.policy_manager.create_policy(name=data['name'], description=data.get('description'))
        return json.dumps({"id": str(policy.id)})

    @log_function_calls(logger=logger)
    def list_policies(self) -> str:
        """
        List all policies.

        Returns:
            str: JSON response containing a list of policy objects.
        """
        policy_list = [p.model_dump() for p in self.policy_manager.get_all_policies()]
        return json.dumps(policy_list)
