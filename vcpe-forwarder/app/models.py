from pydantic import BaseModel


class RouteRequest(BaseModel):
    destination: str
    gateway: str


class RouteDeleteRequest(BaseModel):
    destination: str
    gateway: str | None = None


class InterfaceAddressRequest(BaseModel):
    address: str  # Example: 192.168.10.1/24


class RuleRequest(BaseModel):
    table: str
    fwmark: str | None = None
    priority: int | None = None
    src: str | None = None
    dst: str | None = None
    iif: str | None = None
    oif: str | None = None


class NatMasqueradeRequest(BaseModel):
    out_interface: str
    source_subnet: str | None = None


class BridgeCreateRequest(BaseModel):
    name: str


class BridgePortRequest(BaseModel):
    interface: str    