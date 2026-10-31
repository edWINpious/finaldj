"""Synthetic, in-memory business data. Every name, email, order and file here is fake."""

from __future__ import annotations

USERS: dict[int, dict] = {
    1001: {"id": 1001, "username": "j.miller", "name": "Jordan Miller", "role": "partner",
           "email": "j.miller@halden-freight.example", "company": "Brightwater Imports"},
    1002: {"id": 1002, "username": "a.okafor", "name": "Ada Okafor", "role": "partner",
           "email": "a.okafor@halden-freight.example", "company": "Okafor Textiles"},
    1003: {"id": 1003, "username": "s.lindqvist", "name": "Sven Lindqvist", "role": "ops",
           "email": "s.lindqvist@halden-freight.example", "company": "Halden Freight"},
}

USER_BY_NAME = {u["username"]: u for u in USERS.values()}

SHIPMENTS: dict[int, dict] = {
    50211: {"id": 50211, "owner_id": 1001, "origin": "Rotterdam", "destination": "Gdansk",
            "status": "In transit", "eta": "2026-11-04", "containers": 2},
    50212: {"id": 50212, "owner_id": 1001, "origin": "Hamburg", "destination": "Oslo",
            "status": "Customs hold", "eta": "2026-11-07", "containers": 1},
    50318: {"id": 50318, "owner_id": 1002, "origin": "Antwerp", "destination": "Riga",
            "status": "Delivered", "eta": "2026-10-28", "containers": 4},
}

ORDERS: dict[int, dict] = {
    9001: {"id": 9001, "owner_id": 1001, "shipment_id": 50211, "amount_eur": 4120.00, "state": "invoiced"},
    9002: {"id": 9002, "owner_id": 1001, "shipment_id": 50212, "amount_eur": 1875.50, "state": "open"},
    9003: {"id": 9003, "owner_id": 1002, "shipment_id": 50318, "amount_eur": 9930.00, "state": "paid"},
}

# /download serves ONLY these exact keys from memory. Request input never reaches the filesystem.
FAKE_FILES: dict[str, tuple[str, str]] = {
    "manifest-template.csv": (
        "text/csv",
        "shipment_id,container,weight_kg,hs_code\n50211,HFCU1234567,18400,8471.30\n",
    ),
    "partner-onboarding.txt": (
        "text/plain",
        "Halden Freight partner onboarding checklist (sample).\n1. Request portal account.\n",
    ),
}

API_INDEX = {
    "service": "halden-partner-api",
    "version": "v1",
    "endpoints": ["/api/v1/users", "/api/v1/users/{id}", "/api/v1/orders", "/api/v1/preview"],
}
