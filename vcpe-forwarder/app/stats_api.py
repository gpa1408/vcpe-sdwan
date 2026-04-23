from pathlib import Path

from fastapi import APIRouter

from app.kernel import ensure_interface_exists, read_int_file

router = APIRouter(tags=["stats"])


@router.get("/interfaces/{name}/stats")
def get_interface_stats(name: str):
    ensure_interface_exists(name)

    base = Path(f"/sys/class/net/{name}/statistics")

    stats = {
        "rx_bytes": read_int_file(base / "rx_bytes"),
        "tx_bytes": read_int_file(base / "tx_bytes"),
        "rx_packets": read_int_file(base / "rx_packets"),
        "tx_packets": read_int_file(base / "tx_packets"),
        "rx_errors": read_int_file(base / "rx_errors"),
        "tx_errors": read_int_file(base / "tx_errors"),
        "rx_dropped": read_int_file(base / "rx_dropped"),
        "tx_dropped": read_int_file(base / "tx_dropped"),
    }

    return {
        "interface": name,
        "stats": stats,
    }