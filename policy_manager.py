import uuid
from typing import List

from log_config import logging
from data_types import Policy, PolicyType
from decorators import validate_policy_exists, log_function_calls


logger = logging.getLogger(__name__)


class PolicyManager:
    def __init__(self) -> None:
        self.arupa_policies_by_name = {}  # Dictionary to store policies by their names
        self.policies_by_id = {}  # Dictionary to store policies by their IDs

    def validate_arupa_unique_policy_name(self, policy, exclude_policy_id_check=None) -> None:
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

    @log_function_calls(logger=logger)
    def create_policy(self, name: str, policy_type: PolicyType, description: str = '') -> Policy:
        """
        Create a new policy and store it.

        Args:
            name (str): The name of the policy to be created.
            policy_type (PolicyType): The type of the policy.
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

        del self.policies_by_id[policy_id]
        if policy.is_arupa_policy():
            del self.arupa_policies_by_name[policy.name]

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
