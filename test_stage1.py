import json

import pytest
from stage1 import PolicyAPI


@pytest.fixture
def api():
    return PolicyAPI()


class TestCreatePolicy:
    def test_empty_input(self, api):
        with pytest.raises(Exception):
            api.create_policy("")

    def test_malformed_json_input(self, api):
        with pytest.raises(Exception):
            api.create_policy("{foo")

    def test_returns_valid_json(self, api):
        policy_json = api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                }
            )
        )
        assert isinstance(policy_json, str)
        json.loads(policy_json)

    def test_two_policies_with_different_names(self, api):
        foo_policy_json = api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                }
            )
        )
        bar_policy_json = api.create_policy(
            json.dumps(
                {
                    "name": "bar",
                    "description": "my bar policy",
                }
            )
        )
        foo_policy_identifier = json.loads(foo_policy_json)
        bar_policy_identifier = json.loads(bar_policy_json)
        assert foo_policy_identifier != bar_policy_identifier

    def test_missing_field(self, api):
        with pytest.raises(Exception):
            api.create_policy(json.dumps({"name": "foo"}))

    @pytest.mark.parametrize(
        "invalid_name",
        [
            None,
            {"foo": "bar"},
            ["foo"],
            "foo bar",
            "foo!",
            "toolong" * 10,
        ],
    )
    def test_name_validation(self, api, invalid_name):
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": invalid_name,
                        "description": "my foo policy",
                    }
                )
            )

    def test_name_must_be_unique(self, api):
        api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                }
            )
        )
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": "foo",
                        "description": "another foo policy",
                    }
                )
            )

    @pytest.mark.parametrize(
        "invalid_description",
        [
            None,
            123,
            ["abcd"]
        ],
    )
    def test_description_validation(self, api, invalid_description):
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": "name",
                        "description": invalid_description,
                    }
                )
            )


class TestListPolicies:
    def test_returns_json(self, api):
        policies_json = api.list_policies()
        assert isinstance(policies_json, str)
        json.loads(policies_json)

    def test_returns_json_list(self, api):
        policies_json = api.list_policies()
        policies = json.loads(policies_json)
        assert isinstance(policies, list)

    def test_returns_empty_list(self, api):
        policies = json.loads(api.list_policies())
        assert len(policies) == 0

    def test_list_one(self, api):
        api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                }
            )
        )
        policies = json.loads(api.list_policies())
        assert len(policies) == 1
        [policy] = policies
        assert isinstance(policy, dict)
        assert policy["name"] == "foo"
        assert policy["description"] == "my foo policy"

    def test_list_multiple(self, api):
        api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                }
            )
        )
        api.create_policy(
            json.dumps(
                {
                    "name": "bar",
                    "description": "my bar policy",
                }
            )
        )
        assert len(json.loads(api.list_policies())) == 2

    def test_failed_policy_creation_is_idempotent(self, api):
        api.create_policy(
            json.dumps(
                {
                    "name": "foo",
                    "description": "my foo policy",
                }
            )
        )
        first_response = api.list_policies()
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": "foo",
                        "description": "another foo policy",
                    }
                )
            )
        with pytest.raises(Exception):
            api.create_policy(
                json.dumps(
                    {
                        "name": "invalid!",
                        "description": "another foo policy",
                    }
                )
            )
        assert api.list_policies() == first_response
