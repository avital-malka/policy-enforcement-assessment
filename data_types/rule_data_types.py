from uuid import uuid4
from pydantic import conint, field_serializer
from ipaddress import IPv4Network, IPv4Address

from data_types.base_data_types import BaseModel


class Rule(BaseModel):
    name: str
    ip_proto: conint(ge=0, le=255)  # IP protocol number (0-255)
    source_port: conint(ge=0, le=65535)  # Port number (0-65535)


class ArupaRule(Rule):
    source_subnet: IPv4Network

    @field_serializer('source_subnet')
    def serialize_source_subnet(self, source_subnet: uuid4, _info) -> str:
        return str(source_subnet)


class FriscoRule(Rule):
    source_ip: IPv4Address
    destination_ip: IPv4Address

    @field_serializer('source_ip')
    def serialize_source_ip(self, source_ip: IPv4Address, _info) -> str:
        return str(source_ip)

    @field_serializer('destination_ip')
    def serialize_destination_ip(self, destination_ip: IPv4Address, _info) -> str:
        return str(destination_ip)