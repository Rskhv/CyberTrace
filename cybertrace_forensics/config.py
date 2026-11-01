"""Configuration for stages 4–7."""

BASELINE_TIME_WINDOW_SECONDS = 120.0
CORRELATION_TIME_WINDOW_SECONDS = 300.0
CORRELATION_THRESHOLD = 0.70

CORRELATION_WEIGHTS = {
    "temporal": 0.20,
    "ip": 0.25,
    "port": 0.15,
    "stage": 0.20,
    "evidence": 0.20,
}

STAGE_ORDER = [
    "RECON",
    "SERVICE_DISCOVERY",
    "CREDENTIAL_ATTACK",
    "EXPLOITATION",
]
