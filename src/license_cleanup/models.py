"""Domain models shared by every module.

All models are plain dataclasses that can be serialised to JSON so that the
Jenkins pipeline can hand state from one stage to the next.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC datetime.

    Naive timestamps are assumed to be UTC. Returns ``None`` for empty values.
    Raises ``ValueError`` for malformed values so that bad data is never
    silently treated as "no usage".
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_timestamp(value: datetime | None) -> str:
    """Format a datetime as an ISO-8601 UTC string (empty string for None)."""
    if value is None:
        return ""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class AssigneeType(str, Enum):
    """Assignee types documented in the JetBrains Account API."""

    USER = "USER"
    SERVER = "SERVER"
    LICENSE_KEY = "LICENSE_KEY"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ADStatus(str, Enum):
    """Result of looking a licensed user up in Active Directory."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    NOT_FOUND = "NOT_FOUND"
    MULTIPLE = "MULTIPLE_MATCHES"
    EXTERNAL = "EXTERNAL_USER"
    ERROR = "LOOKUP_ERROR"
    NOT_CHECKED = "NOT_CHECKED"


class Action(str, Enum):
    """Proposed action for a single license."""

    REVOKE = "REVOKE"
    KEEP = "KEEP"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    SKIP = "SKIP"
    DO_NOT_REVOKE = "DO_NOT_REVOKE"  # e.g. directory lookup failed


class RevocationReason(str, Enum):
    """Why a license was proposed for revocation."""

    AD_DISABLED = "AD_ACCOUNT_DISABLED"
    INACTIVE = "PRODUCT_INACTIVE"
    NONE = ""


class Result(str, Enum):
    """Outcome of the revocation step for one license."""

    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    DRY_RUN = "DRY_RUN_NO_CHANGE"
    REVOKED = "REVOKED"
    FAILED = "FAILED"
    UNCERTAIN = "UNCERTAIN"
    SKIPPED_REVALIDATION = "SKIPPED_AFTER_REVALIDATION"
    ABORTED = "ABORTED"


class Verification(str, Enum):
    """Whether a revocation was independently confirmed via the API."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    PENDING = "PENDING"


@dataclass
class License:
    """A single JetBrains license as returned by the JetBrains Account API."""

    license_id: str
    product_code: str
    product_name: str
    team_id: int | None
    team_name: str
    assignee_type: AssigneeType
    assignee_email: str
    assignee_name: str
    is_available_to_assign: bool | None
    is_suspended: bool | None
    is_trial: bool | None
    last_seen_date: datetime | None
    last_assignment_date: datetime | None
    is_offline_code_generated: bool | None
    subscription_valid_until: datetime | None = None
    license_type: str = ""

    @property
    def is_assigned(self) -> bool:
        """True when the license is currently assigned to anyone."""
        return self.assignee_type not in (AssigneeType.NONE,)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["assignee_type"] = self.assignee_type.value
        for key in ("last_seen_date", "last_assignment_date", "subscription_valid_until"):
            data[key] = format_timestamp(getattr(self, key))
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "License":
        values = dict(data)
        values["assignee_type"] = AssigneeType(values["assignee_type"])
        for key in ("last_seen_date", "last_assignment_date", "subscription_valid_until"):
            values[key] = parse_timestamp(values.get(key))
        return cls(**values)


@dataclass
class ADLookupResult:
    """Outcome of an Active Directory lookup for one email address."""

    email: str
    status: ADStatus
    sam_account_name: str = ""
    user_principal_name: str = ""
    matched_attribute: str = ""
    strong_match: bool = False
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ADLookupResult":
        values = dict(data)
        values["status"] = ADStatus(values["status"])
        return cls(**values)


@dataclass
class Decision:
    """The evaluation of one license against the business rules."""

    license: License
    ad: ADLookupResult
    action: Action
    reason: RevocationReason
    explanation: str
    exclusion_status: str
    threshold: datetime
    days_since_last_usage: int | None
    usage_data_source: str
    result: Result = Result.NOT_ATTEMPTED
    verification: Verification = Verification.NOT_APPLICABLE
    actual_action: str = "NONE"
    error_message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "license": self.license.to_dict(),
            "ad": self.ad.to_dict(),
            "action": self.action.value,
            "reason": self.reason.value,
            "explanation": self.explanation,
            "exclusion_status": self.exclusion_status,
            "threshold": format_timestamp(self.threshold),
            "days_since_last_usage": self.days_since_last_usage,
            "usage_data_source": self.usage_data_source,
            "result": self.result.value,
            "verification": self.verification.value,
            "actual_action": self.actual_action,
            "error_message": self.error_message,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Decision":
        threshold = parse_timestamp(data["threshold"])
        if threshold is None:
            raise ValueError("Decision state is missing its threshold")
        return cls(
            license=License.from_dict(data["license"]),
            ad=ADLookupResult.from_dict(data["ad"]),
            action=Action(data["action"]),
            reason=RevocationReason(data["reason"]),
            explanation=data["explanation"],
            exclusion_status=data["exclusion_status"],
            threshold=threshold,
            days_since_last_usage=data["days_since_last_usage"],
            usage_data_source=data["usage_data_source"],
            result=Result(data["result"]),
            verification=Verification(data["verification"]),
            actual_action=data["actual_action"],
            error_message=data["error_message"],
            extra=data.get("extra", {}),
        )
