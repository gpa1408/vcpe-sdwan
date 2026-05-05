from __future__ import annotations

from pathlib import Path
from typing import Any

from .pamodi_compat_api import router as pamodi_compat_router
from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .models import (
    AccessPoint,
    Bridge,
    BridgeMembershipRequest,
    DhcpServer,
    FlowPolicy,
    InterfaceAddressesRequest,
    InterfaceStateRequest,
    NatDiscoveryRequest,
    NatPolicy,
    Path as ForwardPath,
    PathGroup,
    StaticRouteSet,
    TransactionRequest,
    WireGuardPeer,
    WireGuardTunnel,
)
from .state import ForwarderError, ForwarderStateStore


def create_app(
    root: str | Path | None = None,
    *,
    execute: bool = False,
    use_system_state: bool = True,
) -> FastAPI:
    root_path = Path(root) if root is not None else Path.cwd()
    _ = execute, use_system_state

    store = ForwarderStateStore()

    app = FastAPI(title="SD-WAN Forwarder API", version=store.state.version)
    app.state.root = root_path
    app.state.store = store
    app.include_router(pamodi_compat_router)

    @app.exception_handler(ForwarderError)
    async def handle_forwarder_error(_: Request, exc: ForwarderError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    def respond(payload: Any, status_code: int = 200) -> JSONResponse:
        return JSONResponse(status_code=status_code, content=jsonable_encoder(payload))

    @app.get("/api/v1/health")
    def get_health() -> dict[str, Any]:
        return store.health()

    @app.get("/api/v1/revisions/current")
    def get_current_revision():
        return store.current_revision()

    @app.post("/api/v1/revisions/{revision}/rollback", status_code=202)
    def rollback_revision(revision: str):
        return respond(store.rollback(revision), status_code=202)

    @app.post("/api/v1/transactions")
    def post_transaction(request: TransactionRequest):
        return store.apply_transaction(request)

    @app.get("/api/v1/interfaces")
    def list_interfaces():
        return {"items": store.list_interfaces()}

    @app.get("/api/v1/interfaces/{interface_name}")
    def get_interface(interface_name: str):
        return store.get_interface(interface_name)

    @app.put("/api/v1/interfaces/{interface_name}/state")
    def put_interface_state(interface_name: str, request: InterfaceStateRequest):
        return store.set_interface_state(interface_name, request)

    @app.put("/api/v1/interfaces/{interface_name}/addresses")
    def put_interface_addresses(interface_name: str, request: InterfaceAddressesRequest):
        return store.set_interface_addresses(interface_name, request)

    @app.get("/api/v1/interfaces/{interface_name}/counters")
    def get_interface_counters(interface_name: str):
        return store.get_interface_counters(interface_name)

    @app.get("/api/v1/bridges")
    def list_bridges():
        return {"items": store.list_bridges()}

    @app.post("/api/v1/bridges", status_code=201)
    def create_bridge(bridge: Bridge):
        return respond(store.create_bridge(bridge), status_code=201)

    @app.get("/api/v1/bridges/{bridge_id}")
    def get_bridge(bridge_id: str):
        return store.get_bridge(bridge_id)

    @app.put("/api/v1/bridges/{bridge_id}")
    def put_bridge(bridge_id: str, bridge: Bridge):
        return store.put_bridge(bridge_id, bridge)

    @app.delete("/api/v1/bridges/{bridge_id}", status_code=204)
    def delete_bridge(bridge_id: str) -> Response:
        store.delete_bridge(bridge_id)
        return Response(status_code=204)

    @app.put("/api/v1/bridges/{bridge_id}/members")
    def put_bridge_members(bridge_id: str, request: BridgeMembershipRequest):
        return store.set_bridge_members(bridge_id, request)

    @app.get("/api/v1/tunnels/wireguard")
    def list_tunnels():
        return {"items": store.list_wireguard_tunnels()}

    @app.get("/api/v1/tunnels/wireguard/{tunnel_id}")
    def get_tunnel(tunnel_id: str):
        return store.get_wireguard_tunnel(tunnel_id)

    @app.put("/api/v1/tunnels/wireguard/{tunnel_id}")
    def put_tunnel(tunnel_id: str, tunnel: WireGuardTunnel):
        return store.put_wireguard_tunnel(tunnel_id, tunnel)

    @app.delete("/api/v1/tunnels/wireguard/{tunnel_id}", status_code=204)
    def delete_tunnel(tunnel_id: str) -> Response:
        store.delete_wireguard_tunnel(tunnel_id)
        return Response(status_code=204)

    @app.get("/api/v1/tunnels/wireguard/{tunnel_id}/peers")
    def list_peers(tunnel_id: str):
        return {"items": store.list_wireguard_peers(tunnel_id)}

    @app.get("/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}")
    def get_peer(tunnel_id: str, peer_id: str):
        return store.get_wireguard_peer(tunnel_id, peer_id)

    @app.put("/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}")
    def put_peer(tunnel_id: str, peer_id: str, peer: WireGuardPeer):
        return store.put_wireguard_peer(tunnel_id, peer_id, peer)

    @app.delete("/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}", status_code=204)
    def delete_peer(tunnel_id: str, peer_id: str) -> Response:
        store.delete_wireguard_peer(tunnel_id, peer_id)
        return Response(status_code=204)

    @app.get("/api/v1/paths")
    def list_paths():
        return {"items": store.list_paths()}

    @app.get("/api/v1/paths/{path_id}")
    def get_path(path_id: str):
        return store.get_path(path_id)

    @app.put("/api/v1/paths/{path_id}")
    def put_path(path_id: str, path: ForwardPath):
        return store.put_path(path_id, path)

    @app.delete("/api/v1/paths/{path_id}", status_code=204)
    def delete_path(path_id: str) -> Response:
        store.delete_path(path_id)
        return Response(status_code=204)

    @app.get("/api/v1/path-groups/{path_group_id}")
    def get_path_group(path_group_id: str):
        return store.get_path_group(path_group_id)

    @app.put("/api/v1/path-groups/{path_group_id}")
    def put_path_group(path_group_id: str, group: PathGroup):
        return store.put_path_group(path_group_id, group)

    @app.delete("/api/v1/path-groups/{path_group_id}", status_code=204)
    def delete_path_group(path_group_id: str) -> Response:
        store.delete_path_group(path_group_id)
        return Response(status_code=204)

    @app.get("/api/v1/flow-policies")
    def list_flow_policies():
        return {"items": store.list_flow_policies()}

    @app.get("/api/v1/flow-policies/{policy_id}")
    def get_flow_policy(policy_id: str):
        return store.get_flow_policy(policy_id)

    @app.put("/api/v1/flow-policies/{policy_id}")
    def put_flow_policy(policy_id: str, policy: FlowPolicy):
        return store.put_flow_policy(policy_id, policy)

    @app.delete("/api/v1/flow-policies/{policy_id}", status_code=204)
    def delete_flow_policy(policy_id: str) -> Response:
        store.delete_flow_policy(policy_id)
        return Response(status_code=204)

    @app.get("/api/v1/routes/static/{route_set_id}")
    def get_static_route_set(route_set_id: str):
        return store.get_static_route_set(route_set_id)

    @app.put("/api/v1/routes/static/{route_set_id}")
    def put_static_route_set(route_set_id: str, route_set: StaticRouteSet):
        return store.put_static_route_set(route_set_id, route_set)

    @app.delete("/api/v1/routes/static/{route_set_id}", status_code=204)
    def delete_static_route_set(route_set_id: str) -> Response:
        store.delete_static_route_set(route_set_id)
        return Response(status_code=204)

    @app.get("/api/v1/services/nat/policies/{nat_policy_id}")
    def get_nat_policy(nat_policy_id: str):
        return store.get_nat_policy(nat_policy_id)

    @app.put("/api/v1/services/nat/policies/{nat_policy_id}")
    def put_nat_policy(nat_policy_id: str, nat_policy: NatPolicy):
        return store.put_nat_policy(nat_policy_id, nat_policy)

    @app.delete("/api/v1/services/nat/policies/{nat_policy_id}", status_code=204)
    def delete_nat_policy(nat_policy_id: str) -> Response:
        store.delete_nat_policy(nat_policy_id)
        return Response(status_code=204)

    @app.get("/api/v1/services/dhcp/{server_id}")
    def get_dhcp_server(server_id: str):
        return store.get_dhcp_server(server_id)

    @app.put("/api/v1/services/dhcp/{server_id}")
    def put_dhcp_server(server_id: str, server: DhcpServer):
        return store.put_dhcp_server(server_id, server)

    @app.delete("/api/v1/services/dhcp/{server_id}", status_code=204)
    def delete_dhcp_server(server_id: str) -> Response:
        store.delete_dhcp_server(server_id)
        return Response(status_code=204)

    @app.get("/api/v1/services/ap/{ap_id}")
    def get_access_point(ap_id: str):
        return store.get_access_point(ap_id)

    @app.put("/api/v1/services/ap/{ap_id}")
    def put_access_point(ap_id: str, access_point: AccessPoint):
        return store.put_access_point(ap_id, access_point)

    @app.delete("/api/v1/services/ap/{ap_id}", status_code=204)
    def delete_access_point(ap_id: str) -> Response:
        store.delete_access_point(ap_id)
        return Response(status_code=204)

    @app.post("/api/v1/interfaces/{interface_name}/nat-discovery", status_code=202)
    def post_nat_discovery(interface_name: str, request: NatDiscoveryRequest):
        return respond(store.start_nat_discovery(interface_name, request), status_code=202)

    @app.get("/api/v1/interfaces/{interface_name}/nat-discovery/{task_id}")
    def get_nat_discovery(interface_name: str, task_id: str):
        return store.get_nat_discovery(interface_name, task_id)

    return app