# Decision Policy

The implementation follows the participant-facing contract.

## Required treatment

| Category | Treatment |
|---|---|
| USER_PROFILE | DELETE |
| SECONDARY_IDENTIFIER | DELETE |
| SEARCH_INDEX_ENTRY | DELETE |
| CACHE_ENTRY | DELETE |
| SUPPORT_MESSAGE | REDACT when shared context must be retained |
| SUPPORT_ATTACHMENT | DELETE when subject-only |
| ANALYTICS_PROFILE | ANONYMIZE when attributable |
| PRODUCT_TELEMETRY | ANONYMIZE when attributable |
| USER_EXPORT | DELETE |
| MARKETING_PROFILE | DELETE |
| EMAIL_DELIVERY_LOG | REDACT when it contains user email |
| SECURITY_AUDIT_LOG | RETAIN within retention |
| LEGAL_HOLD_RECORD | RETAIN while hold is active |
| BACKUP_ARCHIVE | RETAIN when restore access can be blocked |
| ACCOUNT_TOMBSTONE | REDACT prohibited direct identifiers |

The agent does not treat a reported workflow status as proof of deletion.
