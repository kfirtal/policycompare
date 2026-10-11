# PolicyCompare

Offline validation of CSM-to-FMC access-rule migration. Imports never authenticate,
read credentials, or make API requests. No firewall configuration write or deployment
methods are implemented. Do not connect to organizational systems without explicit
permission; use a read-only API account when an authorized integration test is arranged.

## Setup and offline tests

Python 3.12+ and Requests are required. Use a working Python installation:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m unittest discover -s tests -v
```

All test responses use synthetic documentation-shaped data and reserved example
addresses. Tests make no network requests and require no Cisco credentials.

On the current workstation the system Python 3.14 installation cannot create a
complete virtual environment. Validation used the bundled Python 3.12 runtime and
workspace-local dependencies in `.deps` (ignored by Git):

```powershell
$env:PYTHONPATH = "$PWD\.deps"
& "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m unittest discover -s tests -v
```

## Offline command

```powershell
python compare.py snapshots/source.snapshot.json snapshots/target.snapshot.json
```

Each file is a JSON array of normalized rules, for example:

```json
[
  {
    "rule_number": "1",
    "source_objects": ["example-host"],
    "destination_objects": ["example-subnet"],
    "destination_services": [["6", 443, 443]],
    "action": "ALLOW",
    "enabled": true,
    "object_values": {
      "example-host": ["192.0.2.1/32"],
      "example-subnet": ["198.51.100.0/24"]
    }
  }
]
```

Output is JSON with PASS, FAIL or INDETERMINATE, missing and extra rule details,
changed named network values and affected source/target rule IDs. Exit codes are
0, 1 and 2 respectively. Empty policies require `--allow-empty`; retrieval failures
must never be substituted with empty snapshots. Snapshots are trusted normalized
inputs, not raw Cisco responses. Treat reports and snapshots as internal data.

## Library API and compatibility

`Rule(number, sources, destinations, services)` and `find_gaps(source, target)`
remain available for existing callers. Legacy services such as `"443"` compare
in a separate protocol-unknown namespace; they are not equal to TCP/443 or UDP/443.
Legacy rules without `object_values` still compare names, so a legacy PASS does
not validate actual network values. Prefer client-generated normalized rules.

`compare_rules(source, target)` performs bidirectional comparison. Rule numbers,
list order and duplicate equivalent signatures do not affect equality. Action
and enabled state do affect equality. CIDRs, masks, hosts and IP ranges normalize
to collapsed network sets; adjacent/overlapping TCP or UDP port ranges merge.
Rule splitting/merging across multiple rules is not treated as equivalence.

API functions previously depended on module globals and import-time prompts.
They are now instance methods on `CSMClient` and `FMCClient`. Constructing a client
makes no request. `login(username, password)` explicitly authenticates; credentials
are not stored on the clients. Supply passwords through `getpass` or an approved
secret provider in an authorized caller, never through checked-in files or CLI args.

- `CSMClient('https://example.invalid/nbi')`: `getGIDByName`, `getPolicyList`,
  `getPolicy`, `PolicyRules`, `policy_rules`, `logout`.
- `FMCClient('https://example.invalid', domain='explicit-domain-uuid')`:
  `policy_uuid_by_name`, `policy_rules`. With no domain specified, login requires
  exactly one returned domain; it never silently picks the first of several.
- `compare_policies(csm_client, csm_name, fmc_client, fmc_name)` accepts already
  authenticated clients and returns INDETERMINATE on API or parsing failures.
  The caller owns session lifecycle; put CSM logout in a `finally` block.

The CLI is deliberately offline. Nothing in this repository initiates a live
comparison on execution. Client configuration supports an injected session,
`timeout=30`, and `verify=True` or a custom CA bundle path. Redirects are disabled.
429 retries are bounded to five attempts with bounded Retry-After delays. Other
HTTP failures, expired authentication, and transport errors stop the run with
sanitized exceptions; automatic token refresh is not implemented. Cache lifetimes
are per policy fetch, keyed by object identity rather than name.

## Supported scope and remaining limits

This is a field/signature comparison of Allow/Drop access rules, under the stated
Allow-then-Drop policy model. PASS is not proof of full firewall behavior, device
deployment state, default-action equivalence, NAT, routing, intrusion or file policy
behavior, prefilter policy, or interface/zone mapping. Rule order is ignored as
requested. Verify the policy-model assumption separately for each migration.

Supported referenced values: host, IP network, address range, nested network
groups, TCP/UDP destination services, nested service groups and CSM port lists.
Empty or unresolved objects, cycles, incomplete pages, unsupported protocols,
FQDNs, source-port restrictions, zones/interfaces, identity, time and application
constraints fail or produce INDETERMINATE. Unreviewed nonempty rule fields are
flagged conservatively and may require documented adapter extensions.
Device-specific object overrides and CSM local/device policy retrieval are not
implemented; use shared policies without overrides. CSM service-version negotiation
and FMC-version-specific adapter validation remain integration work. No FMC version
was supplied; generic FMC object and access-rule endpoints were used. Synthetic
fixtures cannot establish compatibility with a particular installed release.

Pagination checks detect repeated IDs, stalled pages, inconsistent totals and
truncation. They cannot ensure a transactionally consistent snapshot while rules
or objects change on the server. Arrange an authorized quiet-window export for
migration validation. Object caches do not persist between policy fetches.

## Documentation used

- [CSM 4.25 API specification, Version 2.4](https://www.cisco.com/c/dam/en/us/td/docs/security/security_management/cisco_security_manager/security_manager/425/API/CSM-API-Spec-v25.pdf): sections 2.2.1.1 (pagination), 2.2.2 (login), 3.1.4 (objects), 3.1.5.1 (access rules), 3.2.8 (shared policy retrieval).
- [FMC 7.4.1 REST objects guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_741/Objects_In_The_REST_API.html): object collections, expanded retrieval and offset/limit parameters. Confirm these against the installed FMC API Explorer before any authorized live validation.

CSM starts pagination without a startIndex; subsequent requests reuse endIndex.
The last page omits endIndex/totalCount. FMC uses offset/limit and collection
paging.count. Both readers verify fetched totals before returning a policy.

## הסבר על שלב האימות

`snapshots.py` אחראי לטעינת קובצי JSON מקומיים. הוא בודק שהקובץ מכיל
מערך חוקים, שהשדות הדרושים קיימים ושהמבנה שלהם תקין. שדות לא מוכרים
נדחים כדי שלא נתעלם בטעות מתנאי חשוב בחוק.

`compare.signature` בודק את משמעות הנתונים לפני יצירת מפתח ההשוואה.
ערכי אובייקט חייבים להיות אוסף כתובות ורשתות, ולא מחרוזת בודדת.
שירות מנורמל מכיל פרוטוקול ושני מספרי פורט שלמים בטווח תקין.
שירות מסוג `any` חייב לכסות את הטווח המלא; טווח מצומצם אינו תקין.
נתון פגום מונע PASS גם כאשר אותו נתון מופיע בשני הצדדים.

תנאי לסיום הפרויקט הוא אימות מתועד מול שרתי CSM ו־FMC במעבדה,
לאחר אישור מפורש להתחבר אליהם. נבדוק התאמה מלאה, פערים מכוונים,
קבוצות מקוננות, דפדוף בתוצאות וכשלי תקשורת והרשאה. הבדיקות המקומיות
אינן מחליפות שלב זה. הכלי עצמו יבצע קריאה בלבד.

## פענוח תשובות ודוחות לקראת המעבדה

ב־FMC מערכי אובייקטים חייבים להיות מערכים של רשומות. שדה אופציונלי חסר
יכול להיות ריק; ערך `null` מפורש או מבנה שגוי נדחים. נבדקים גם סוג המזהה,
התאמת סוג האובייקט לשדה רשת או שירות, והיסט הדף כאשר השרת מחזיר אותו.
ב־CSM שדות חובה חייבים להופיע פעם אחת כערך פשוט. רשימות הפניות,
מכלי מדיניות ובחירות פורט סותרות נבדקים לפני יצירת החוקים.
בשני הלקוחות ניסיון התחברות חדש מבטל תחילה את זהות ההתחברות הישנה.

דוח השוואה כולל `summary` עם מספר החוקים בכל צד ו־`warnings` שמסבירות
את גבולות הבדיקה. בחוקים חסרים ועודפים מופיעים גם `resolved_sources`
ו־`resolved_destinations`; הם `null` בהשוואה לפי שמות בלבד.
כשל באיסוף המדיניות דרך `compare_policies` כולל `error_details` עם שלב
הכשל (`csm_policy_read`, `fmc_policy_lookup`, `fmc_policy_read` או `comparison`)
וקטגוריה כללית. תוכן תגובות השרת ופרטי ההתחברות אינם מועתקים לשגיאה.
הערכים הפתורים בדוחות עצמם הם מידע תשתיתי: יש לשמור דוחות בתוך הארגון
ולצנזר אותם לפני שיתוף. פרטי הפענוח המחמירים עדיין דורשים אימות מול
גרסאות השרתים במעבדה; תשובה תקינה אך לא נתמכת תיחשב כשל עד להוספת תמיכה.
