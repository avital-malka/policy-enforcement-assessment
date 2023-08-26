import json
import pytest

from errors import PolicyNotFoundError, RuleNotFoundError
from stage3 import PolicyAPI


@pytest.fixture
def api():
    return PolicyAPI()


@pytest.fixture
def arupa_policy_identifier(api):
    return api.create_policy(
        json.dumps(
            {
                "name": "foo",
                "description": "my foo policy",
                "type": "Arupa",
            }
        )
    )


@pytest.fixture
def bar_policy_identifier(api):
    return api.create_policy(
        json.dumps(
            {
                "name": "bar",
                "description": "my bar policy",
                "type": "Arupa",
            }
        )
    )


@pytest.fixture
def frisco_policy_identifier(api):
    return api.create_policy(
        json.dumps(
            {
                "name": "foo",
                "description": "my foo policy",
                "type": "Frisco",
            }
        )
    )


@pytest.fixture
def arupa_rule_identifier(api, arupa_policy_identifier):
    rule_data = {
        "name": "arupa_rule",
        "ip_proto": 6,
        "source_port": 8080,
        "source_subnet": "192.168.0.0/24",
    }
    rule_json = json.dumps(rule_data)
    return api.create_rule(arupa_policy_identifier, rule_json)


@pytest.fixture
def frisco_rule_identifier(api, frisco_policy_identifier):
    rule_data = {
        "name": "frisco_rule",
        "ip_proto": 6,
        "source_port": 8080,
        "source_ip": "192.168.0.1",
        "destination_ip": "192.168.0.2",
    }
    rule_json = json.dumps(rule_data)
    return api.create_rule(frisco_policy_identifier, rule_json)



@pytest.fixture
def test_invalid_policy_type(api):
    with pytest.raises(Exception):
        api.create_policy(json.dumps({"name": "policy", "description": "my policy", "type": "InvalidType"}))


class TestCreatePolicy:
    def test_type_validation(self, api):
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": "foo",
                        "description": "my foo policy",
                        "type": "invalid",
                    }
                )
            )

    def test_name_must_be_unique_for_arupa_policies(self, api, arupa_policy_identifier):
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": "foo",
                        "description": "another foo policy",
                        "type": "Arupa",
                    }
                )
            )

    def test_name_can_be_duplicated_for_frisco_policies(self, api):
        first_foo_policy_json = api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                    "type": "Frisco",
                }
            )
        )
        another_foo_policy_json = api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "another foo policy",
                    "type": "Frisco",
                }
            )
        )
        first_foo_policy_identifier = json.loads(first_foo_policy_json)
        another_foo_policy_identifier = json.loads(another_foo_policy_json)
        assert first_foo_policy_identifier != another_foo_policy_identifier


class TestReadPolicy:
    def test_invalid_or_nonexistent_identifier(self, api):
        with pytest.raises(Exception):
            api.read_policy(json.dumps("invalid"))

    def test_consistent_response_for_same_policy(self, api, arupa_policy_identifier):
        assert api.read_policy(arupa_policy_identifier) == api.read_policy(
            arupa_policy_identifier
        )

    def test_different_response_for_different_policies(
        self, api, arupa_policy_identifier, bar_policy_identifier
    ):
        assert api.read_policy(arupa_policy_identifier) != api.read_policy(
            bar_policy_identifier
        )

    def test_returns_valid_json(self, api, arupa_policy_identifier):
        json.loads(api.read_policy(arupa_policy_identifier))

    def test_returns_dict_with_fields(self, api, arupa_policy_identifier):
        policy = json.loads(api.read_policy(arupa_policy_identifier))
        assert isinstance(policy, dict)
        assert policy["name"] == "foo"
        assert policy["description"] == "my foo policy"
        assert policy["type"] == "Arupa"


class TestUpdatePolicy:
    def test_invalid_or_nonexistent_identifier(self, api):
        with pytest.raises(Exception):
            api.update_policy(
                json.dumps("invalid"),
                json.dumps(
                    {
                        "name": "foo",
                        "description": "my foo policy",
                        "type": "Arupa",
                    }
                ),
            )

    def test_invalid_fields(self, api, arupa_policy_identifier):
        with pytest.raises(Exception):
            api.update_policy(
                arupa_policy_identifier,
                json.dumps(
                    {
                        "name": "bar",
                        "description": "my foo policy",
                        "type": "invalid",
                    }
                ),
            )

    def test_update_description(self, api, arupa_policy_identifier):
        api.update_policy(
            arupa_policy_identifier,
            json.dumps(
                {
                    "name": "foo",
                    "description": "my bar policy",
                    "type": "Arupa",
                }
            ),
        )
        updated_policy = json.loads(api.read_policy(arupa_policy_identifier))
        assert updated_policy["name"] == "foo"
        assert updated_policy["description"] == "my bar policy"
        assert updated_policy["type"] == "Arupa"

    def test_failed_update_is_idempotent(self, api, arupa_policy_identifier):
        foo_policy = api.read_policy(arupa_policy_identifier)
        with pytest.raises(Exception):
            api.update_policy(
                arupa_policy_identifier,
                json.dumps(
                    {
                        "name": "foo",
                        "description": "my foo policy",
                        "type": "invalid",
                    }
                ),
            )
        assert api.read_policy(arupa_policy_identifier) == foo_policy

    def test_empty_update(self, api, arupa_policy_identifier):
        updated_policy = api.update_policy(arupa_policy_identifier, json.dumps({}))
        assert updated_policy == api.read_policy(arupa_policy_identifier)

    def test_same_values_update(self, api, arupa_policy_identifier):
        updated_policy = api.update_policy(
            arupa_policy_identifier, json.dumps({"name": "foo", "description": "my foo policy", "type": "Arupa"})
        )
        assert updated_policy == api.read_policy(arupa_policy_identifier)


class TestDeletePolicy:
    def test_no_read_or_update_after_delete(self, api, arupa_policy_identifier):
        api.read_policy(arupa_policy_identifier)
        api.delete_policy(arupa_policy_identifier)
        with pytest.raises(Exception):
            api.read_policy(arupa_policy_identifier)
        with pytest.raises(Exception):
            api.update_policy(
                arupa_policy_identifier,
                json.dumps(
                    {
                        "name": "bar",
                        "description": "my foo policy",
                        "type": "Arupa",
                    }
                ),
            )

    @staticmethod
    def test_delete_nonexistent_policy(api):
        with pytest.raises(Exception):
            api.delete_policy(json.dumps({"id": "nonexistent_id"}))


class TestListPolicies:
    @staticmethod
    def test_list_empty_policies(api):
        policies = json.loads(api.list_policies())
        assert len(policies) == 0

    def test_list_one(self, api, arupa_policy_identifier):
        policies = json.loads(api.list_policies())
        assert len(policies) == 1
        [policy] = policies
        assert isinstance(policy, dict)
        assert policy["name"] == "foo"
        assert policy["description"] == "my foo policy"
        assert policy["type"] == "Arupa"

    def test_list_multiple(self, api, arupa_policy_identifier, bar_policy_identifier):
        assert len(json.loads(api.list_policies())) == 2


class TestCreateRule:
    def test_create_arupa_rule(self, api, arupa_policy_identifier):
        rule_data = {
            "name": "arupa_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_subnet": "192.168.0.0/24",
        }
        rule_json = json.dumps(rule_data)
        rule_identifier = api.create_rule(arupa_policy_identifier, rule_json)
        assert isinstance(json.loads(rule_identifier), dict)

    def test_create_frisco_rule(self, api, frisco_policy_identifier):
        rule_data = {
            "name": "frisco_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_ip": "192.168.0.1",
            "destination_ip": "10.0.0.1",
        }
        rule_json = json.dumps(rule_data)
        rule_identifier = api.create_rule(frisco_policy_identifier, rule_json)
        assert isinstance(json.loads(rule_identifier), dict)

    def test_invalid_policy_identifier(self, api):
        rule_data = {
            "name": "test_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_subnet": "192.168.0.0/24",
        }
        rule_json = json.dumps(rule_data)
        with pytest.raises(Exception):
            api.create_rule("invalid_identifier", rule_json)

    def test_invalid_rule_data(self, api, arupa_policy_identifier):
        invalid_rule_json = json.dumps({"invalid_field": "value"})
        with pytest.raises(Exception):
            api.create_rule(arupa_policy_identifier, invalid_rule_json)

    def test_arupa_rule_name_unique_within_policy(self, api, arupa_policy_identifier):
        rule_data = {
            "name": "unique_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_subnet": "192.168.0.0/24",
        }
        rule_json = json.dumps(rule_data)
        api.create_rule(arupa_policy_identifier, rule_json)

        with pytest.raises(Exception):
            api.create_rule(arupa_policy_identifier, rule_json)

    def test_frisco_rule_name_globally_unique(self, api, frisco_policy_identifier):
        rule_data = {
            "name": "unique_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_ip": "192.168.0.1",
            "destination_ip": "192.168.0.2",
        }
        rule_json = json.dumps(rule_data)
        api.create_rule(frisco_policy_identifier, rule_json)

        with pytest.raises(Exception):
            another_policy_identifier = api.create_policy(
                json.dumps({"name": "another_policy", "type": "Frisco", "description": "policy description"})
            )
            api.create_rule(another_policy_identifier, rule_json)


class TestReadRule:
    def test_invalid_or_nonexistent_identifier(self, api):
        with pytest.raises(Exception):
            api.read_rule(json.dumps("invalid"))

    def test_read_arupa_rule(self, api, arupa_policy_identifier):
        rule_data = {
            "name": "test_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_subnet": "192.168.0.0/24",
        }
        rule_json = json.dumps(rule_data)
        rule_identifier = api.create_rule(arupa_policy_identifier, rule_json)

        actual_rule_data = json.loads(api.read_rule(rule_identifier))
        assert actual_rule_data.pop('id')
        assert actual_rule_data == rule_data

    def test_read_frisco_rule(self, api, frisco_policy_identifier):
        rule_data = {
            "name": "test_rule",
            "ip_proto": 6,
            "source_port": 8080,
            "source_ip": "192.168.0.1",
            "destination_ip": "192.168.0.2",
        }
        rule_json = json.dumps(rule_data)
        rule_identifier = api.create_rule(frisco_policy_identifier, rule_json)

        actual_rule_data = json.loads(api.read_rule(rule_identifier))
        assert actual_rule_data.pop('id')
        assert actual_rule_data == rule_data


class TestListRules:
    def test_list_rules_invalid_identifier(self, api):
        with pytest.raises(ValueError):
            api.list_rules("invalid_identifier")

    def test_list_rules_nonexistent_policy(self, api):
        invalid_policy_id = "00000000-0000-0000-0000-000000000000"
        with pytest.raises(PolicyNotFoundError):
            api.list_rules(json.dumps({"id": str(invalid_policy_id)}))

    def assert_rule_properties(self, rule, expected_name, expected_proto, expected_port, **kwargs):
        assert rule["name"] == expected_name
        assert rule["ip_proto"] == expected_proto
        assert rule["source_port"] == expected_port
        for key, value in kwargs.items():
            assert rule.get(key) == value

    def _test_list_rules(self, api, policy_identifier, rule_data_list):
        for rule_data in rule_data_list:
            api.create_rule(policy_identifier, json.dumps(rule_data))

        rules_json = api.list_rules(policy_identifier)
        rules = json.loads(rules_json)
        assert isinstance(rules, list)
        assert len(rules) == len(rule_data_list)

        for i, rule in enumerate(rules):
            self.assert_rule_properties(
                rule,
                rule_data_list[i]["name"],
                rule_data_list[i]["ip_proto"],
                rule_data_list[i]["source_port"],
                source_subnet=rule_data_list[i].get("source_subnet"),
                source_ip=rule_data_list[i].get("source_ip"),
                destination_ip=rule_data_list[i].get("destination_ip")
            )

    def test_list_arupa_rules(self, api, arupa_policy_identifier):
        rule_data_list = [
            {
                "name": "arupa_rule_1",
                "ip_proto": 6,
                "source_port": 8080,
                "source_subnet": "192.168.0.0/24",
            },
            {
                "name": "arupa_rule_2",
                "ip_proto": 17,
                "source_port": 12345,
                "source_subnet": "10.0.0.0/8",
            },
            {
                "name": "arupa_rule_3",
                "ip_proto": 1,
                "source_port": 5555,
                "source_subnet": "172.16.0.0/16",
            }
        ]
        self._test_list_rules(api, arupa_policy_identifier, rule_data_list)

    def test_list_frisco_rules(self, api, frisco_policy_identifier):
        rule_data_list = [
            {
                "name": "frisco_rule_1",
                "ip_proto": 6,
                "source_port": 8080,
                "source_ip": "192.168.1.1",
                "destination_ip": "10.1.1.1",
            },
            {
                "name": "frisco_rule_2",
                "ip_proto": 17,
                "source_port": 12345,
                "source_ip": "10.2.2.2",
                "destination_ip": "172.16.1.1",
            },
            {
                "name": "frisco_rule_3",
                "ip_proto": 1,
                "source_port": 5555,
                "source_ip": "172.16.2.2",
                "destination_ip": "192.168.2.2",
            }
        ]
        self._test_list_rules(api, frisco_policy_identifier, rule_data_list)

    class TestDeleteRule:
        def test_delete_arupa_rule(self, api, arupa_rule_identifier):
            api.delete_rule(arupa_rule_identifier)
            with pytest.raises(RuleNotFoundError):
                api.read_rule(arupa_rule_identifier)

        def test_delete_frisco_rule(self, api, frisco_rule_identifier):
            api.delete_rule(frisco_rule_identifier)
            with pytest.raises(RuleNotFoundError):
                api.read_rule(frisco_rule_identifier)

        def test_delete_invalid_rule(self, api):
            invalid_rule_id = "00000000-0000-0000-0000-000000000000"
            with pytest.raises(RuleNotFoundError):
                api.delete_rule(json.dumps({"id": invalid_rule_id}))

    class TestUpdateRule:
        @staticmethod
        def assert_rule_properties(rule_data, **expected_properties):
            for property_name, expected_value in expected_properties.items():
                actual_value = rule_data.get(property_name)
                assert actual_value == expected_value, f"Property '{property_name}' mismatch. Expected: {expected_value}, Actual: {actual_value}"

        def _test_update_rule(self, api, policy_identifier, rule_data):
            rule_json = json.dumps(rule_data)
            rule_identifier = api.create_rule(policy_identifier, rule_json)

            updated_data = {
                "name": f"updated_rule",
                "ip_proto": rule_data["ip_proto"] + 1,
                "source_port": rule_data["source_port"] + 1,
                **rule_data.get("additional_fields", {})  # Use specific rule type fields if available
            }
            updated_rule_json = json.dumps(updated_data)
            api.update_rule(rule_identifier, updated_rule_json)

            updated_rule = api.read_rule(rule_identifier)
            updated_rule_data = json.loads(updated_rule)
            self.assert_rule_properties(updated_rule_data, **updated_data)

        def test_update_arupa_rule(self, api, arupa_policy_identifier):
            rule_data = {
                "name": "arupa_rule",
                "ip_proto": 6,
                "source_port": 8080,
                "source_subnet": "192.168.0.0/24",
            }
            self._test_update_rule(api, arupa_policy_identifier, rule_data)

        def test_update_frisco_rule(self, api, frisco_policy_identifier):
            rule_data = {
                "name": "frisco_rule",
                "ip_proto": 6,
                "source_port": 8080,
                "source_ip": "192.168.1.1",
                "destination_ip": "10.0.0.1",
            }
            self._test_update_rule(api, frisco_policy_identifier, rule_data)
