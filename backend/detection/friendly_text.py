"""Professional explanations and recommendations for alert types."""

from typing import Tuple


def explain(alert_type: str) -> Tuple[str, str]:
    """Return (explanation, recommendation) in professional tone."""
    mapping = {
        "dns_tunneling": (
            "Unusual volume or pattern of DNS requests was observed.",
            "Review the device for unexpected activity. If possible, update firmware and restrict outbound DNS to the router.",
        ),
        "telnet_activity": (
            "Connections were initiated on Telnet (TCP/23), an outdated and insecure protocol.",
            "Disable Telnet or remove the service. If not required, block TCP/23 at the router.",
        ),
        "rare_destination": (
            "Connections to an uncommon external endpoint were detected for this device.",
            "Confirm whether this traffic is expected. If not, limit access to approved destinations.",
        ),
        "port_scan_like": (
            "Short bursts to many ports suggest scanning behaviour.",
            "Investigate the device and limit outbound connectivity if the behaviour persists.",
        ),
    }
    return mapping.get(
        alert_type,
        (
            "Anomalous network activity detected.",
            "Review device behaviour and apply network restrictions if necessary.",
        ),
    )

