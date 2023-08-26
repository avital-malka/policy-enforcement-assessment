class PolicyNotFoundError(Exception):
    """Exception raised when a policy with a specific ID is not found."""

    def __init__(self, policy_id):
        super().__init__(f"Policy with ID '{policy_id}' not found.")


class RuleNotFoundError(Exception):
    """Exception raised when a rule with a specific ID is not found."""

    def __init__(self, policy_id):
        super().__init__(f"Rule with ID '{policy_id}' not found.")
