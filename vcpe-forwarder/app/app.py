from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .pamodi_compat_api import router as pamodi_compat_router
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
from .service import ForwarderError, ForwarderService
from .state import ForwarderStateStore


def create_app(
    root: str | Path | None = None,
    *,
    execute: bool = False,
    use_system_state: bool = True,
) -> FastAPI:
    root_path = Path(root) if root is not None else Path.cwd()

    if os.getenv("FORWARDER_EXECUTE", "0").lower() in {"1", "true", "yes", "on"}:
        execute = True

    service = ForwarderService(
        root_path,
        execute=execute,
        use_system_state=use_system_state,
    )

    # Legacy store solo para pamodi_compat_api.py.
    # La API formal /api/v1 usa ForwarderService.
    legacy_store = ForwarderStateStore()

    app = FastAPI(title="SD-WAN Forwarder API", version=service.version)
    app.state.root = root_path
    app.state.service = service
    app.state.store = legacy_store
    app.include_router(pamodi_compat_router)

    @app.exception_handler(ForwarderError)
    async def handle_forwarder_error(_: Request, exc: ForwarderError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    def respond(payload: Any, status_code: int = 200) -> JSONResponse:
        return JSONResponse(status_code=status_code, content=jsonable_encoder(payload))

    def service_get(path: str):
        return service.apply_operation("GET", path, None).body

    def service_put(path: str, payload: dict[str, Any]):
        return service.apply_operation("PUT", path, payload).body

    def service_post(path: str, payload: dict[str, Any]):
        return service.apply_operation("POST", path, payload).body

    def service_delete(path: str) -> None:
        service.apply_operation("DELETE", path, None)

    # ---------------------------------------------------------------------
    # Core
    # ---------------------------------------------------------------------

    @app.get("/api/v1/health")
    def get_health() -> dict[str, Any]:
        return service.health()

    @app.get("/api/v1/revisions/current")
    def get_current_revision():
        return service.current_revision()

    @app.post("/api/v1/revisions/{revision}/rollback", status_code=202)
    def rollback_revision(revision: str):
        return respond(service.rollback(revision), status_code=202)

    @app.post("/api/v1/transactions")
    def post_transaction(request: TransactionRequest):
        return service.process_transaction(request)

    # ---------------------------------------------------------------------
    # Interfaces
    # ---------------------------------------------------------------------

    @app.get("/api/v1/interfaces")
    def list_interfaces():
        return service_get("/api/v1/interfaces")

    @app.get("/api/v1/interfaces/{interface_name}")
    def get_interface(interface_name: str):
        return service_get(f"/api/v1/interfaces/{interface_name}")

    @app.put("/api/v1/interfaces/{interface_name}/state")
    def put_interface_state(interface_name: str, request: InterfaceStateRequest):
        return service_put(
            f"/api/v1/interfaces/{interface_name}/state",
            request.model_dump(mode="json"),
        )

    @app.put("/api/v1/interfaces/{interface_name}/addresses")
    def put_interface_addresses(interface_name: str, request: InterfaceAddressesRequest):
        return service_put(
            f"/api/v1/interfaces/{interface_name}/addresses",
            request.model_dump(mode="json"),
        )

    @app.get("/api/v1/interfaces/{interface_name}/counters")
    def get_interface_counters(interface_name: str):
        return service_get(f"/api/v1/interfaces/{interface_name}/counters")

    # ---------------------------------------------------------------------
    # Bridges
    # ---------------------------------------------------------------------

    @app.get("/api/v1/bridges")
    def list_bridges():
        return service_get("/api/v1/bridges")

    @app.post("/api/v1/bridges", status_code=201)
    def create_bridge(bridge: Bridge):
        return respond(
            service_post("/api/v1/bridges", bridge.model_dump(mode="json")),
            status_code=201,
        )

    @app.get("/api/v1/bridges/{bridge_id}")
    def get_bridge(bridge_id: str):
        return service_get(f"/api/v1/bridges/{bridge_id}")

    @app.put("/api/v1/bridges/{bridge_id}")
    def put_bridge(bridge_id: str, bridge: Bridge):
        return service_put(
            f"/api/v1/bridges/{bridge_id}",
            bridge.model_dump(mode="json"),
        )

    @app.delete("/api/v1/bridges/{bridge_id}", status_code=204)
    def delete_bridge(bridge_id: str) -> Response:
        service_delete(f"/api/v1/bridges/{bridge_id}")
        return Response(status_code=204)

    @app.put("/api/v1/bridges/{bridge_id}/members")
    def put_bridge_members(bridge_id: str, request: BridgeMembershipRequest):
        return service_put(
            f"/api/v1/bridges/{bridge_id}/members",
            request.model_dump(mode="json"),
        )

    # ---------------------------------------------------------------------
    # WireGuard
    # ---------------------------------------------------------------------

    @app.get("/api/v1/tunnels/wireguard")
    def list_tunnels():
        return service_get("/api/v1/tunnels/wireguard")

    @app.get("/api/v1/tunnels/wireguard/{tunnel_id}")
    def get_tunnel(tunnel_id: str):
        return service_get(f"/api/v1/tunnels/wireguard/{tunnel_id}")

    @app.put("/api/v1/tunnels/wireguard/{tunnel_id}")
    def put_tunnel(tunnel_id: str, tunnel: WireGuardTunnel):
        return service_put(
            f"/api/v1/tunnels/wireguard/{tunnel_id}",
            tunnel.model_dump(mode="json"),
        )

    @app.delete("/api/v1/tunnels/wireguard/{tunnel_id}", status_code=204)
    def delete_tunnel(tunnel_id: str) -> Response:
        service_delete(f"/api/v1/tunnels/wireguard/{tunnel_id}")
        return Response(status_code=204)

    @app.get("/api/v1/tunnels/wireguard/{tunnel_id}/peers")
    def list_peers(tunnel_id: str):
        return service_get(f"/api/v1/tunnels/wireguard/{tunnel_id}/peers")

    @app.get("/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}")
    def get_peer(tunnel_id: str, peer_id: str):
        return service_get(f"/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}")

    @app.put("/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}")
    def put_peer(tunnel_id: str, peer_id: str, peer: WireGuardPeer):
        return service_put(
            f"/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}",
            peer.model_dump(mode="json"),
        )

    @app.delete("/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}", status_code=204)
    def delete_peer(tunnel_id: str, peer_id: str) -> Response:
        service_delete(f"/api/v1/tunnels/wireguard/{tunnel_id}/peers/{peer_id}")
        return Response(status_code=204)

    # ---------------------------------------------------------------------
    # Paths / Path Groups
    # ---------------------------------------------------------------------

    @app.get("/api/v1/paths")
    def list_paths():
        return service_get("/api/v1/paths")

    @app.get("/api/v1/paths/{path_id}")
    def get_path(path_id: str):
        return service_get(f"/api/v1/paths/{path_id}")

    @app.put("/api/v1/paths/{path_id}")
    def put_path(path_id: str, path: ForwardPath):
        return service_put(
            f"/api/v1/paths/{path_id}",
            path.model_dump(mode="json"),
        )

    @app.delete("/api/v1/paths/{path_id}", status_code=204)
    def delete_path(path_id: str) -> Response:
        service_delete(f"/api/v1/paths/{path_id}")
        return Response(status_code=204)

    @app.get("/api/v1/path-groups/{path_group_id}")
    def get_path_group(path_group_id: str):
        return service_get(f"/api/v1/path-groups/{path_group_id}")

    @app.put("/api/v1/path-groups/{path_group_id}")
    def put_path_group(path_group_id: str, group: PathGroup):
        return service_put(
            f"/api/v1/path-groups/{path_group_id}",
            group.model_dump(mode="json"),
        )

    @app.delete("/api/v1/path-groups/{path_group_id}", status_code=204)
    def delete_path_group(path_group_id: str) -> Response:
        service_delete(f"/api/v1/path-groups/{path_group_id}")
        return Response(status_code=204)

    # ---------------------------------------------------------------------
    # Flow Policies
    # ---------------------------------------------------------------------

    @app.get("/api/v1/flow-policies")
    def list_flow_policies():
        return service_get("/api/v1/flow-policies")

    @app.get("/api/v1/flow-policies/{policy_id}")
    def get_flow_policy(policy_id: str):
        return service_get(f"/api/v1/flow-policies/{policy_id}")

    @app.put("/api/v1/flow-policies/{policy_id}")
    def put_flow_policy(policy_id: str, policy: FlowPolicy):
        return service_put(
            f"/api/v1/flow-policies/{policy_id}",
            policy.model_dump(mode="json"),
        )

    @app.delete("/api/v1/flow-policies/{policy_id}", status_code=204)
    def delete_flow_policy(policy_id: str) -> Response:
        service_delete(f"/api/v1/flow-policies/{policy_id}")
        return Response(status_code=204)

    # ---------------------------------------------------------------------
    # Static Routes
    # ---------------------------------------------------------------------

    @app.get("/api/v1/routes/static/{route_set_id}")
    def get_static_route_set(route_set_id: str):
        return service_get(f"/api/v1/routes/static/{route_set_id}")

    @app.put("/api/v1/routes/static/{route_set_id}")
    def put_static_route_set(route_set_id: str, route_set: StaticRouteSet):
        return service_put(
            f"/api/v1/routes/static/{route_set_id}",
            route_set.model_dump(mode="json"),
        )

    @app.delete("/api/v1/routes/static/{route_set_id}", status_code=204)
    def delete_static_route_set(route_set_id: str) -> Response:
        service_delete(f"/api/v1/routes/static/{route_set_id}")
        return Response(status_code=204)

    # ---------------------------------------------------------------------
    # NAT / DHCP / AP
    # ---------------------------------------------------------------------

    @app.get("/api/v1/services/nat/policies/{nat_policy_id}")
    def get_nat_policy(nat_policy_id: str):
        return service_get(f"/api/v1/services/nat/policies/{nat_policy_id}")

    @app.put("/api/v1/services/nat/policies/{nat_policy_id}")
    def put_nat_policy(nat_policy_id: str, nat_policy: NatPolicy):
        return service_put(
            f"/api/v1/services/nat/policies/{nat_policy_id}",
            nat_policy.model_dump(mode="json"),
        )

    @app.delete("/api/v1/services/nat/policies/{nat_policy_id}", status_code=204)
    def delete_nat_policy(nat_policy_id: str) -> Response:
        service_delete(f"/api/v1/services/nat/policies/{nat_policy_id}")
        return Response(status_code=204)

    @app.get("/api/v1/services/dhcp/{server_id}")
    def get_dhcp_server(server_id: str):
        return service_get(f"/api/v1/services/dhcp/{server_id}")

    @app.put("/api/v1/services/dhcp/{server_id}")
    def put_dhcp_server(server_id: str, server: DhcpServer):
        return service_put(
            f"/api/v1/services/dhcp/{server_id}",
            server.model_dump(mode="json"),
        )

    @app.delete("/api/v1/services/dhcp/{server_id}", status_code=204)
    def delete_dhcp_server(server_id: str) -> Response:
        service_delete(f"/api/v1/services/dhcp/{server_id}")
        return Response(status_code=204)

    @app.get("/api/v1/services/ap/{ap_id}")
    def get_access_point(ap_id: str):
        return service_get(f"/api/v1/services/ap/{ap_id}")

    @app.put("/api/v1/services/ap/{ap_id}")
    def put_access_point(ap_id: str, access_point: AccessPoint):
        return service_put(
            f"/api/v1/services/ap/{ap_id}",
            access_point.model_dump(mode="json"),
        )

    @app.delete("/api/v1/services/ap/{ap_id}", status_code=204)
    def delete_access_point(ap_id: str) -> Response:
        service_delete(f"/api/v1/services/ap/{ap_id}")
        return Response(status_code=204)

    # ---------------------------------------------------------------------
    # NAT discovery is direct, not inside /api/v1/transactions
    # ---------------------------------------------------------------------

    @app.post("/api/v1/interfaces/{interface_name}/nat-discovery", status_code=202)
    def post_nat_discovery(interface_name: str, request: NatDiscoveryRequest):
        return respond(service.start_nat_discovery(interface_name, request), status_code=202)

    @app.get("/api/v1/interfaces/{interface_name}/nat-discovery/{task_id}")
    def get_nat_discovery(interface_name: str, task_id: str):
        return service_get(f"/api/v1/interfaces/{interface_name}/nat-discovery/{task_id}")

    return app