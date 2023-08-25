from typing import List

from log_config import logging
from data_types import Policy
from decorators import log_function_calls


logger = logging.getLogger(__name__)


class PolicyManager:
    def __init__(self) -> None:
        self.policies_by_name = {}  # Dictionary to store policies by their names
        self.policies_by_id = {}    # Dictionary to store policies by their IDs

    def validate_unique_policy_name(self, policy_name):
        """
        Validate the uniqueness of a policy name.

        Checks whether a policy with the given name already exists in the collection.

        Args:
            policy_name (str): The policy name to be validated.

        Raises:
            ValueError: If a policy with the same name already exists.
        """
        if policy_name in self.policies_by_name:
            raise ValueError(f"A policy with the name '{policy_name}' already exists. Please choose a unique name.")

    def get_all_policies(self) -> List[Policy]:
        """
        Retrieve a list of all policies.

        Returns:
            List[Policy]: A list containing all policy objects.
        """
        return list(self.policies_by_id.values())

    def store_policy(self, policy: Policy) -> None:
        """
         Store a policy in the policy manager.

         Args:
             policy (Policy): The policy to be stored.

         Returns:
             None
         """
        self.policies_by_name[policy.name] = policy
        self.policies_by_id[policy.id] = policy

    @log_function_calls(logger=logger)
    def create_policy(self, name: str, description: str = '') -> Policy:
        """
        Create a new policy and store it.

        Args:
            name (str): The name of the policy to be created.
            description (str, optional): The description of the policy. Defaults to ''.

        Returns:
            Policy: The created policy.

        Raises:
            ValueError: If the policy name is not unique.
        """
        self.validate_unique_policy_name(name)
        policy = Policy(name=name, description=description)
        self.store_policy(policy)
        return policy
