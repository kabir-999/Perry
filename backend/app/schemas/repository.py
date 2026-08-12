import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class SourceFindingRead(BaseModel):
    """A single issue found in the repository's source code.

    `code_context` is the redacted source line the issue was found on — it is
    what the UI renders as a code block. Secret values are never returned.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    repository_id: Optional[uuid.UUID] = None

    finding_type: str
    file: str
    line: int
    severity: str
    confidence: str
    evidence: str
    secret_type: str = ""
    redacted_value: str = ""
    code_context: str = ""

    package: str = ""
    version: str = ""
    ecosystem: str = ""
    advisory_id: str = ""
    fixed_version: str = ""

    # Exploitability context for dependency findings: what was established
    # about this application, as opposed to what the advisory says.
    classification: str = ""
    vulnerable_range: str = ""
    is_direct: bool = False
    is_used: bool = False
    externally_reachable: str = ""

    created_at: datetime


class RepositoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    provider: str
    owner: str
    name: str
    url: str
    confidence: float
    status: str
    files_analyzed: int
    error_message: str
    created_at: datetime
