from typing import TypeVar, Any
from uuid import uuid4

from pydantic import BaseModel as PydanticBaseModel, Field, field_serializer

# Define a type variable _BaseModel, constrained to be a subclass of the BaseModel class
_BaseModel = TypeVar('_BaseModel', bound='BaseModel')


class BaseModel(PydanticBaseModel):
    id: uuid4 = Field(default_factory=uuid4)

    @field_serializer('id')
    def serialize_id(self, id: uuid4, _info) -> str:
        return str(id)

    def model_copy(self: _BaseModel, *, update: dict[str, Any] | None = None, deep: bool = False) -> _BaseModel:
        """
        Create a shallow or deep copy of the model instance.

        Args:
            update (dict[str, Any] | None, optional): A dictionary of attributes to update in the copied instance.
            Defaults to None.
            deep (bool, optional): If True, perform a deep copy by copying nested structures.
            If False, perform a shallow copy. Defaults to False.

        Returns:
            _BaseModel: A copy of the model instance.

        Note:
            This method creates a copy of the model instance. It is used to create a new instance with the same data
            and optionally update specific attributes. It also validates the copied instance using `model_validate`
            method.

        Todo:
            Follow the issue at https://github.com/pydantic/pydantic/issues/418 for a better approach.
        """
        copy = super().model_copy(update=update, deep=deep)

        self.model_validate(
            dict(copy.model_dump(exclude_unset=True, by_alias=False))
        )
        return copy
