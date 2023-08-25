from uuid import uuid4
from pydantic import BaseModel, Field, field_serializer


class Policy(BaseModel):
    """
    A policy is a group of definitions of what traffic is allowed or forbidden.
    """
    id: uuid4 = Field(default_factory=uuid4)
    name: str = Field(..., max_length=32, pattern=r'^[a-zA-Z0-9_]+$')
    description: str

    @field_serializer('id')
    def serialize_id(self, id: uuid4, _info) -> str:
        return str(id)
