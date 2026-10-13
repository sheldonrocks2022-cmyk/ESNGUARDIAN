# ESNG AI independent language support

The Python ESNG conversation engine is fully local. It does not use a third-party AI API, hosted model, or model download.

## Usage in Discord

- `ESNG hola` — Spanish greeting and language selection
- `ESNG bonjour` — French greeting and language selection
- `ESNG こんにちは` — Japanese greeting and language selection
- `ESNG language es` — explicitly select Spanish for your session
- `ESNG calculate 3*(4+2)` — localized calculation result
- `ESNG reset conversation` — clear your temporary conversation history

Supported starter locale catalogs: en, es, fr, de, pt, it, ja, ko, zh, ar, hi, ru, tr.

## Scope and limitations

This is a **localization foundation**, not general multilingual fluency. Only the authored catalog strings are translated. Existing Guardian slash commands, audit messages, security reports, and long-form ESNG answers remain primarily English until individually migrated. Unrecognized languages fall back to English.

Language and conversation context are per guild and user, held in memory only, and reset when the bot restarts. They are not persistent user profiles. The engine is deterministic, not a trained large language model.

For additional languages, add reviewed strings to `esn_guardian/localization.py`, extend its tests, and migrate user-facing strings through `translate()`. Do not translate or reinterpret permission gates or enforcement logic.
