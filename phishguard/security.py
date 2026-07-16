"""Central security limits for untrusted email and enrichment processing."""

# Input limits keep malformed or intentionally oversized messages from
# exhausting memory, CPU, or external-enrichment quotas.
MAX_EMAIL_BYTES = 25 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_MIME_PARTS = 200
MAX_BODY_CHARS = 1_000_000
MAX_ATTACHMENTS = 100
MAX_URLS = 200

# Batch and external-enrichment limits cap aggregate local and third-party
# workload. Enrichment is explicit and disabled by default.
MAX_BATCH_FILES = 100
MAX_BATCH_BYTES = 250 * 1024 * 1024
MAX_ENRICHED_BATCH_FILES = 10
MAX_IP_ENRICHMENTS = 10
MAX_URL_ENRICHMENTS = 3


class EmailLimitError(ValueError):
    """Raised when an untrusted message exceeds a documented safety limit."""
