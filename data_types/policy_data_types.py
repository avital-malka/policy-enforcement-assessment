from typing import List
from pydantic import Field

from data_types.base_data_types import BaseModel
from data_types.consts import NetworkTrafficType
from data_types.rule_data_types import Rule


class Policy(BaseModel):
    name: str = Field(..., max_length=32, pattern=r'^[a-zA-Z0-9_]+$')
    description: str
    type: NetworkTrafficType
    rules: List[Rule] = Field(default_factory=list)

    @staticmethod
    def validate_instance(policy):
        Policy.model_validate(policy, from_attributes=True, strict=True)

    def is_arupa_policy(self) -> bool:
        return self.type == NetworkTrafficType.ARUPA

