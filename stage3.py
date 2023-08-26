import json

from uuid import UUID

from log_config import logging
from decorators import validate_json_fields, log_function_calls
from managers.policy_manager import PolicyManager
from managers.rule_manager import RuleManager

logger = logging.getLogger(__name__)


class PolicyAPI:
    def __init__(self) -> None:
        self.rule_manager = RuleManager()
        self.policy_manager = PolicyManager(self.rule_manager)

    @staticmethod
    def get_id_from_json_identifier(json_identifier) -> UUID:
        """
        Get a UUID from a JSON identifier string.

        Args:
            json_identifier (str): JSON identifier string containing the UUID.

        Returns:
            UUID: The UUID extracted from the JSON identifier.
        """
        id_str = json.loads(json_identifier)['id']
        return UUID(id_str)

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
        policy_id = self.get_id_from_json_identifier(json_identifier)
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
        policy_id = self.get_id_from_json_identifier(json_identifier)
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
        policy_id = self.get_id_from_json_identifier(json_identifier)
        self.policy_manager.delete_policy(policy_id)

    @log_function_calls(logger=logger)
    def create_rule(self, json_policy_identifier: str, json_rule_input: str) -> str:
        """
        Create a new rule and associate it with a policy.

        Args:
            json_policy_identifier (str): JSON input containing policy identifier.
            json_rule_input (str): JSON input containing rule data.

        Returns:
            str: JSON response containing the ID of the created rule.
        """
        rule_data = json.loads(json_rule_input)
        policy_id = self.get_id_from_json_identifier(json_policy_identifier)

        rule = self.policy_manager.create_rule(policy_id, rule_data)
        return json.dumps(rule.model_dump())

    @log_function_calls(logger=logger)
    def read_rule(self, json_identifier: str) -> str:
        """
        Retrieve a rule using its JSON identifier.

        Args:
            json_identifier (str): JSON input containing rule details.

        Returns:
            str: JSON response with the retrieved rule details.

        Raises:
            ValueError: If the JSON input is not in the expected format.
            RuleNotFoundError: If a rule with the specified ID is not found.
        """
        rule_id = self.get_id_from_json_identifier(json_identifier)
        policy = self.rule_manager.get_rule(rule_id)
        return json.dumps(policy.model_dump())

    @log_function_calls(logger=logger)
    def update_rule(self, json_identifier: str, json_rule_input: str) -> str:
        """
        Update a rule based on the provided JSON input.

        Args:
            json_identifier (str): JSON input containing the rule identifier.
            json_rule_input (str): JSON input containing the updated rule data.

        Returns:
            str: JSON response containing the updated rule.

        Raises:
            RuleNotFoundError: If the rule with the specified ID is not found.
            ValueError: If the JSON input is not in the expected format.
        """
        data = json.loads(json_rule_input)
        rule_id = self.get_id_from_json_identifier(json_identifier)
        rule = self.rule_manager.get_rule(rule_id)

        updated_rule = self.policy_manager.update_rule(rule, data)
        return json.dumps(updated_rule.model_dump())

    @log_function_calls(logger=logger)
    def delete_rule(self, json_identifier: str) -> None:
        rule_id = self.get_id_from_json_identifier(json_identifier)
        self.policy_manager.delete_rule_from_policy(rule_id)

    @log_function_calls(logger=logger)
    def list_rules(self, json_policy_identifier: str) -> str:
        """
        List all rules associated with a policy.

        Args:
            json_policy_identifier (str): JSON input containing policy identifier.

        Returns:
            str: JSON response containing a list of rules associated with the policy.

        Raises:
            ValueError: If the JSON input is not in the expected format.
            PolicyNotFoundError: If a policy with the specified ID is not found.
        """
        policy_id = self.get_id_from_json_identifier(json_policy_identifier)
        rules = [r.model_dump() for r in self.policy_manager.get_policy_rules(policy_id)]
        return json.dumps(rules)
