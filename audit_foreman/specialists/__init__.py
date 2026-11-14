from audit_foreman.specialists.access import AccessSpecialist
from audit_foreman.specialists.base import Specialist
from audit_foreman.specialists.billing import BillingSpecialist
from audit_foreman.specialists.network import NetworkSpecialist

DEFAULT_SPECIALISTS: dict[str, Specialist] = {
    "network": NetworkSpecialist(),
    "billing": BillingSpecialist(),
    "access": AccessSpecialist(),
}

__all__ = [
    "Specialist",
    "NetworkSpecialist",
    "BillingSpecialist",
    "AccessSpecialist",
    "DEFAULT_SPECIALISTS",
]
