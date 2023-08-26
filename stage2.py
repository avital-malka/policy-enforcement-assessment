import json

from uuid import UUID

from log_config import logging
from decorators import validate_json_fields, log_function_calls
from policy_manager import PolicyManager


logger = logging.getLogger(__name__)


class PolicyAPI:
    def __init__(self) -> None:
        self.policy_manager = PolicyManager()

    @staticmethod
    def get_policy_id_from_json_identifier(json_identifier) -> UUID:
        """
        Extracts and returns the UUID of a policy from a JSON identifier.

        Args:
            json_identifier (str): JSON input containing policy identifier.

        Returns:
            UUID: The UUID of the policy extracted from the JSON identifier.
        """
        policy_id_str = json.loads(json_identifier)['id']
        return UUID(policy_id_str)

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
        policy = self.policy_manager.create_policy(
            name=data['name'],
            policy_type=data['type'],
            description=data.get('description')
        )
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

    @validate_json_fields(expected_fields=["id"])
    @log_function_calls(logger=logger)
    def read_policy(self, json_identifier: str) -> str:
        """
        Retrieve a policy using its ID provided in the JSON input.

        Args:
            json_identifier (str): JSON input containing policy details.

        Returns:
            str: JSON response with the retrieved policy details.

        Raises:
            ValueError: If the JSON input is not in the expected format.
            PolicyNotFoundError: If a policy with the specified ID is not found.
        """
        policy_id = self.get_policy_id_from_json_identifier(json_identifier)
        policy = self.policy_manager.get_policy(policy_id)
        return json.dumps(policy.model_dump())

    @validate_json_fields(expected_fields=["id"])
    @log_function_calls(logger=logger)
    def update_policy(self, json_identifier: str, json_input: str) -> str:
        """
        Update a policy using its ID provided in the JSON input.

        Args:
            json_identifier (str): JSON input containing policy ID.
            json_input (str): JSON input containing updated policy fields.

        Returns:
            str: JSON response with the updated policy details.

        Raises:
            ValueError: If the JSON input is not in the expected format.
            PolicyNotFoundError: If a policy with the specified ID is not found.
        """
        policy_id = self.get_policy_id_from_json_identifier(json_identifier)
        data = json.loads(json_input)
        policy = self.policy_manager.update_policy(policy_id, data)
        return json.dumps(policy.model_dump())

    @validate_json_fields(expected_fields=["id"])
    @log_function_calls(logger=logger)
    def delete_policy(self, json_identifier: str) -> None:
        """
        Update a policy using its ID provided in the JSON input.

        Args:
            json_identifier (str): JSON input containing policy ID.
            json_input (str): JSON input containing updated policy fields.

        Returns:
            str: JSON response with the updated policy details.

        Raises:
            ValueError: If the JSON input is not in the expected format.
            PolicyNotFoundError: If a policy with the specified ID is not found.
        """
        policy_id = self.get_policy_id_from_json_identifier(json_identifier)
        self.policy_manager.delete_policy(policy_id)