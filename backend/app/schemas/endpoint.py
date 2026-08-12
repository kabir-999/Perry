import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class DiscoveredEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    url: str
    method: str
    source: str
    discovery_method: str
    status_code: Optional[int] = None
    content_type: str
    response_size: Optional[int] = None
    created_at: datetime


class SubdomainRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    hostname: str
    resolved_ip: str
    source: str
    created_at: datetime
