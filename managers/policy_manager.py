import uuid
from typing import List

from log_config import logging
from data_types.consts import NetworkTrafficType
from data_types.rule_data_types import Rule
from data_types.policy_data_types import Policy
from decorators import validate_policy_exists, log_function_calls, validate_rule_exists
from managers.rule_manager import RuleManager

logger = logging.getLogger(__name__)


class PolicyManager:
    def __init__(self, rule_manager: RuleManager) -> None:
        self.rule_manager = rule_manager

        self.policies_by_id = {}
        self.rules_policies = {}
        self.arupa_policies_by_name = {}
        self.frisco_policies_by_name = {}

    def validate_arupa_unique_policy_name(self, policy: Policy, exclude_policy_id_check=None) -> None:
        """
        Validate that arupa policy with the given name does not already exist.

        Args:
            policy (Policy): The policy to be validated.
            exclude_policy_id_check (uuid.UUID, optional): ID of the policy to exclude from validation.

        Raises:
            ValueError: If a policy with the given name already exists and is not excluded by ID.
        """
        name = policy.name
        if name in self.arupa_policies_by_name:
            if not exclude_policy_id_check or self.arupa_policies_by_name[name].id != exclude_policy_id_check:
                raise ValueError(f"A policy with the name '{name}' already exists. Please choose a unique name.")

    def get_all_policies(self) -> List[Policy]:
        """
        Retrieve a list of all policies.

        Returns:
            List[Policy]: A list containing all policy objects.
        """
        return list(self.policies_by_id.values())

    @log_function_calls(logger=logger)
    def store_or_update_policy(self, policy: Policy, update_policy: bool = False) -> None:
        """
        Store or update a policy in the policy manager.

        Args:
            policy (Policy): The policy to be stored or updated.
            update_policy (bool, optional): Flag indicating whether to update the policy. Defaults to False.

        Returns:
            None

        Raises:
            ValueError: If a policy with the same name already exists when updating.
        """
        if update_policy:
            exclude_policy_id_check = policy.id
        else:
            exclude_policy_id_check = None
        self.validate_arupa_unique_policy_name(policy, exclude_policy_id_check)

        self.policies_by_id[policy.id] = policy
        if policy.is_arupa_policy():
            self.arupa_policies_by_name[policy.name] = policy
        else:
            self.frisco_policies_by_name[policy.name] = policy

    @log_function_calls(logger=logger)
    def create_policy(self, name: str, policy_type: NetworkTrafficType, description: str = '') -> Policy:
        """
        Create a new policy and store it.

        Args:
            name (str): The name of the policy to be created.
            policy_type (NetworkTrafficType): The type of the policy.
            description (str, optional): The description of the policy. Defaults to ''.

        Returns:
            Policy: The created policy.

        Raises:
            ValidationError: If the provided fields are not valid for the Policy class.
        """
        policy = Policy(name=name, type=policy_type, description=description)
        self.store_or_update_policy(policy)
        return policy

    @validate_policy_exists
    @log_function_calls(logger=logger)
    def get_policy(self, policy_id: uuid.UUID) -> Policy:
        """
        Retrieve a policy using its ID.

        Args:
            policy_id (uuid.UUID): The ID of the policy to retrieve.

        Returns:
            Policy: The policy with the specified ID.

        Raises:
            PolicyNotFound: If a policy with the specified ID is not found.
        """
        return self.policies_by_id[policy_id]

    def _delete_policy_rules(self, rules) -> None:
        for rule in rules:
            policy = self.rules_policies[rule.id]

            policy.rules.remove(rule)
            del self.rules_policies[rule.id]
            self.rule_manager.delete_rule(rule.id)

    @validate_policy_exists
    @log_function_calls(logger=logger)
    def delete_policy(self, policy_id: uuid.UUID) -> None:
        """
        Delete a policy using its ID.

        Args:
            policy_id (uuid.UUID): The ID of the policy to delete.

        Raises:
            PolicyNotFoundError: If a policy with the specified ID is not found.
        """
        policy = self.get_policy(policy_id)
        self._delete_policy_rules(policy.rules)

        del self.policies_by_id[policy_id]
        if policy.is_arupa_policy():
            del self.arupa_policies_by_name[policy.name]
        else:
            del self.frisco_policies_by_name[policy.name]

    @validate_policy_exists
    @log_function_calls(logger=logger)
    def update_policy(self, policy_id: uuid.UUID, fields_to_update: dict) -> Policy:
        """
        Update fields of a policy using its ID.

        Args:
            policy_id (uuid.UUID): The ID of the policy to update.
            fields_to_update (dict): Dictionary of fields to update.

        Returns:
            Policy: The updated policy object.

        Raises:
            PolicyNotFoundError: If a policy with the specified ID is not found.
            ValidationError: If the fields_to_update are not valid for the Policy class.
        """
        policy = self.get_policy(policy_id)

        new_fields = {field: value for field, value in fields_to_update.items() if field != 'id'}
        temp_policy = policy.model_copy(update=new_fields)
        self.store_or_update_policy(temp_policy, update_policy=True)
        return temp_policy

    @staticmethod
    def is_rule_name_exists_in_policy(policy: Policy, rule_name: str, exclude_rule_id: uuid.UUID = None) -> bool:
        """
        Check if a rule name exists within the policy's rules while excluding a specific rule ID.

        Args:
            policy (Policy): The policy containing the rules.
            rule_name (str): The rule name to check.
            exclude_rule_id (uuid.UUID, optional): ID of the rule to exclude from the check.

        Returns:
            bool: True if the rule name exists, False otherwise.
        """
        return any(rule.name == rule_name for rule in policy.rules if rule.id != exclude_rule_id)

    def is_rule_name_exists_between_policies(self, rule_name: str, policy_type: NetworkTrafficType,
                                             exclude_rule_id: uuid.UUID = None) -> bool:
        """
        Check if a rule name exists among policies of a certain type.

        Args:
            rule_name (str): The rule name to check.
            policy_type (NetworkTrafficType): The type of policies to check (Arupa or Frisco).
            exclude_rule_id (uuid.UUID, optional): ID of the rule to exclude from the check.

        Returns:
            bool: True if the rule name exists in any policy of the specified type, False otherwise.
        """
        policies = (self.arupa_policies_by_name.values() if policy_type == NetworkTrafficType.ARUPA
                    else self.frisco_policies_by_name.values())
        for policy in policies:
            if self.is_rule_name_exists_in_policy(policy, rule_name, exclude_rule_id):
                return True
        return False

    def validate_rule_name(self, policy, rule_name, exclude_rule_id=None) -> None:
        """
        Validate the uniqueness of a rule name within policies of the same type.

        Args:
            policy (Policy): The policy containing the rules.
            rule_name (str): The rule name to validate.
            exclude_rule_id (uuid.UUID, optional): ID of the rule to exclude from validation.

        Raises:
            ValueError: If a rule with the same name already exists within policies of the same type.
        """
        if policy.type == NetworkTrafficType.ARUPA:
            if self.is_rule_name_exists_in_policy(policy, rule_name, exclude_rule_id):
                raise ValueError(f"A Rule with the name '{rule_name}' already exists in policy {policy.id}. Please choose another rule name.")

        elif policy.type == NetworkTrafficType.FRISCO:
            if self.is_rule_name_exists_between_policies(rule_name, NetworkTrafficType.FRISCO, exclude_rule_id):
                raise ValueError(f"A Rule with the name '{rule_name}' already exists. Please choose another rule name.")

    @log_function_calls(logger=logger)
    def create_rule(self, policy_id: uuid.UUID, rule_data: dict) -> Rule:
        """
        Create a new rule and associate it with a policy.

        Args:
            policy_id (uuid.UUID): ID of the policy to associate the rule with.
            rule_data (dict): Data for the new rule.

        Returns:
            Rule: The newly created rule.

        Raises:
            ValueError: If the rule name is not unique within the policy.
        """
        policy = self.get_policy(policy_id)
        self.validate_rule_name(policy, rule_data.get('name'))

        rule = self.rule_manager.create_rule(rule_data, policy.type)
        policy.rules.append(rule)
        self.rules_policies[rule.id] = policy
        return rule

    @log_function_calls(logger=logger)
    def update_rule(self, rule_to_update: Rule, rule_data: dict) -> Rule:
        """
        Update a rule within the associated policy.

        Args:
            rule_to_update (Rule): The rule to be updated.
            rule_data (dict): The updated rule data.

        Returns:
            Rule: The updated rule.

        Raises:
            RuleNameConflictError: If the updated rule name conflicts with other rules within the policy.
        """
        policy = self.rules_policies[rule_to_update.id]
        self.validate_rule_name(policy, rule_data.get('name'), exclude_rule_id=rule_data.get('id'))

        updated_rule = self.rule_manager.update_rule(rule_to_update, rule_data)
        policy.rules.remove(rule_to_update)
        policy.rules.append(updated_rule)

        return updated_rule

    @validate_policy_exists
    @log_function_calls(logger=logger)
    def get_policy_rules(self, policy_id) -> List[Rule]:
        """
        Retrieve the rules associated with a policy.

        Args:
            policy_id (uuid.UUID): The ID of the policy.

        Returns:
            List[Rule]: A list of rules associated with the specified policy.

        Raises:
            PolicyNotFoundError: If a policy with the specified ID is not found.
        """
        policy = self.get_policy(policy_id)
        return policy.rules

    @validate_rule_exists
    def delete_rule_from_policy(self, rule_id) -> None:
        """
        Delete a rule from its associated policy.

        Args:
            rule_id (uuid.UUID): ID of the rule to be deleted from its policy.

        Raises:
            RuleNotFoundError: If the specified rule ID is not found.
        """
        rule = self.rule_manager.get_rule(rule_id)
        self._delete_policy_rules([rule])


