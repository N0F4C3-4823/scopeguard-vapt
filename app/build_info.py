"""Build and policy identifiers exposed by the running application."""

APP_VERSION = "1.0.0-beta.1"
BUILD_ID = "scopeguard-2026.11.09-manual-review-parallel"
CLASSIFICATION_POLICY_VERSION = "classification-v3-external-accessibility"
ASSESSMENT_WORKER_VERSION = "worker-v3-evidence-reconciliation"
FRONTEND_BUILD_ID = "frontend-2026.11.09-manual-review-parallel"


def as_dict() -> dict[str, str]:
    return {
        "app_version": APP_VERSION,
        "build_id": BUILD_ID,
        "classification_policy_version": CLASSIFICATION_POLICY_VERSION,
        "assessment_worker_version": ASSESSMENT_WORKER_VERSION,
        "frontend_build_id": FRONTEND_BUILD_ID,
    }
