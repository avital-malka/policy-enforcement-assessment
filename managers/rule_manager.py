from typing import List

from decorators import log_function_calls
from log_config import logging
from data_types.consts import NetworkTrafficType
from errors import RuleNotFoundError
from data_types.rule_data_types import ArupaRule, FriscoRule, Rule

logger = logging.getLogger(__name__)


class RuleManager:
    def __init__(self) -> None:
        self.rules_by_id = {}  # Dictionary to store rules by their IDs

    def delete_rule(self, rule_id):
        del self.rules_by_id[rule_id]

    def store_rule(self, rule):
        self.rules_by_id[rule.id] = rule

    @staticmethod
    @log_function_calls(logger=logger)
    def create_arupa_rule(name, ip_proto, source_port, source_subnet) -> ArupaRule:
        """
        Create a new Arupa rule.

        Args:
            name (str): The name of the rule.
            ip_proto (int): The IP protocol number.
            source_port (int): The source port number.
            source_subnet (IPv4Network): The source IP subnet.

        Returns:
            ArupaRule: The created Arupa rule instance.
        """
        arupa_rule = ArupaRule(
            name=name,
            ip_proto=ip_proto,
            source_port=source_port,
            source_subnet=source_subnet,
        )
        return arupa_rule

    @staticmethod
    @log_function_calls(logger=logger)
    def create_frisco_rule(name, ip_proto, source_port, source_ip, destination_ip) -> FriscoRule:
        """
        Create a new Frisco rule.

        Args:
            name (str): The name of the rule.
            ip_proto (int): The IP protocol number.
            source_port (int): The source port number.
            source_ip (IPv4Address): The source IP address.
            destination_ip (IPv4Address): The destination IP address.

        Returns:
            FriscoRule: The created Frisco rule instance.
        """
        frisco_rule = FriscoRule(
            name=name,
            ip_proto=ip_proto,
            source_port=source_port,
            source_ip=source_ip,
            destination_ip=destination_ip,
        )
        return frisco_rule

    @log_function_calls(logger=logger)
    def create_rule(self, rule_data, network_traffic_type) -> Rule:
        """
        Create a new rule based on the network traffic type.

        Args:
            rule_data (dict): Data for the rule.
            network_traffic_type (NetworkTrafficType): The type of network traffic.

        Returns:
            Rule: The created rule instance.
        """
        name = rule_data.get("name")
        ip_proto = rule_data.get("ip_proto")
        source_port = rule_data.get("source_port")

        if network_traffic_type == NetworkTrafficType.ARUPA:
            source_subnet = rule_data.get("source_subnet")
            rule =  self.create_arupa_rule(name, ip_proto, source_port, source_subnet)
        elif network_traffic_type == NetworkTrafficType.FRISCO:
            source_ip = rule_data.get("source_ip")
            destination_ip = rule_data.get("destination_ip")
            rule = self.create_frisco_rule(name, ip_proto, source_port, source_ip, destination_ip)
        else:
            raise ValueError("Invalid network traffic type")

        self.store_rule(rule)
        return rule

    @log_function_calls(logger=logger)
    def get_rule(self, rule_id) -> Rule:
        """
        Get a rule by its ID.

        Args:
            rule_id: The ID of the rule to retrieve.

        Returns:
            Rule: The rule with the specified ID.

        Raises:
            RuleNotFoundError: If the rule ID is not found in the rules dictionary.
        """
        try:
            return self.rules_by_id[rule_id]
        except KeyError:
            raise RuleNotFoundError(rule_id)

    def get_all_rules(self) -> List[Rule]:
        """
        Retrieve a list of all rules.

        Returns:
            List[Rule]: A list containing all rule objects.
        """
        return list(self.rules_by_id.values())

    @log_function_calls(logger=logger)
    def update_rule(self, rule_to_update, rule_data) -> Rule:
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
        # verify rule exists
        self.get_rule(rule_to_update.id)

        new_fields = {field: value for field, value in rule_data.items() if field != 'id'}
        temp_rule = rule_to_update.model_copy(update=new_fields)
        self.store_rule(temp_rule)
        return temp_rule
