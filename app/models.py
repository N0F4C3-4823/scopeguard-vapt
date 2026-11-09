from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Status = Literal["FOUND", "NOT_FOUND", "NA", "INCONCLUSIVE"]
AssessmentStatus = Literal[
    "DRAFT",
    "QUEUED",
    "RUNNING",
    "PAUSED",
    "CANCELLED",
    "COMPLETED",
    "FAILED",
]


class AssessmentCreate(BaseModel):
    name: str = Field(default="Untitled assessment", min_length=1, max_length=120)
    client_name: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=1000)
    targets: list[str] = Field(min_length=1, max_length=256)
    excludes: list[str] = Field(default_factory=list, max_length=256)
    target_labels: dict[str, str] = Field(default_factory=dict)
    authorized: bool = False
    authorization_note: str = Field(default="", max_length=500)
    profile: Literal["controlled_fixture", "authorized_external"] = "controlled_fixture"
    assessment_type: Literal[
        "external_unauthenticated",
        "internal_unauthenticated",
        "internal_authenticated",
        "custom_hybrid",
    ] = "external_unauthenticated"
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    permissions: list[str] = Field(default_factory=list, max_length=32)
    credentials_available: bool = False
    llm_enabled: bool = False
    evidence_screenshots: bool = True

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Assessment name cannot be blank")
        return value


class AssessmentControl(BaseModel):
    action: Literal["start", "pause", "resume", "cancel"]


class TargetModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    value: str
    label: str
    kind: str
    host_count: int
    excluded: bool = False


class EventModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    assessment_id: str
    created_at: str
    event: str
    phase: str
    message: str
    status: str | None = None
    testcase_id: str | None = None
    target_id: str | None = None
    completed_units: int = 0
    total_units: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)


class ResultModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    assessment_id: str
    target_id: str
    target: str
    target_label: str
    testcase_id: str
    testcase_name: str
    status: Status
    applicability: str
    conditions_tested: list[str]
    conditions_confirmed: list[str]
    conditions_not_found: list[str]
    inconclusive_conditions: list[str]
    severity: str
    finding_ids: list[str]
    evidence_paths: list[str]
    poc_paths: list[str]
    tools_used: list[str]
    validation_state: str
    failure_reason: str | None
    evidence_id: str | None
    command: str | None
    output_preview: str | None
    created_at: str


class AssessmentModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    client_name: str = ""
    description: str = ""
    status: AssessmentStatus
    profile: str
    assessment_type: str
    capabilities: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    credentials_available: bool = False
    authorized: bool
    authorization_note: str
    created_at: str
    started_at: str | None
    completed_at: str | None
    target_count: int
    completed_units: int
    total_units: int
    found_count: int
    not_found_count: int
    na_count: int
    inconclusive_count: int
    applicable_count: int
    error_count: int
    current_phase: str
    current_target: str | None
    current_testcase: str | None
    llm_enabled: bool


class AssessmentDetail(AssessmentModel):
    targets: list[TargetModel]
    results: list[ResultModel]
    recent_events: list[EventModel]


class TriageModel(BaseModel):
    testcase_id: str
    observation_ids: list[str]
    interpretation: str
    suggested_action_id: str | None = None
    explanation: str
    limitations: list[str] = Field(default_factory=list)
    requires_additional_evidence: bool = False
