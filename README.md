# PolicyCompare - CSM to FMC synchronization review

CSM is the source of truth. FMC was initially populated by a one-time copy, while policy changes continued in CSM. This tool identifies the resulting drift so an engineer can review the corrections required in FMC.

This edition keeps the application in four Python files. The previous extended edition is preserved in [archive/extended-policycompare](https://github.com/kfirtal/policycompare/tree/archive/extended-policycompare).

## What is compared

Only three rule fields participate: **src_objects**, **dst_objects**, and **dst_services**. In Python they retain the original names `source_objects`, `destination_objects`, and `destination_services`.

1. **Rule signatures:** source/destination object names and resolved destination protocol/port ranges. Compare in both directions, with CSM authoritative.
2. **Referenced object values:** match named network and service objects by `(kind, name)` and compare their normalized values. Follow groups recursively and include named nested members. A matching rule signature does not pass the overall comparison if an object's value differs.

Hosts and equivalent /32 or /128 prefixes compare equally. Address ranges and subnet unions are normalized. TCP and UDP remain distinct. Adjacent/overlapping service ranges are merged. Group member order is ignored; named nested members are still checked even when their parent group's aggregate value is unchanged.

The initial copy is assumed to have preserved object names. Renamed objects are reported as differences rather than guessed matches. Service names do not enter the rule signature, but named service definitions are checked in the object report. CSM port-list objects supply port values to their parent service; they are not independently matched to FMC object names.

## Report sections

| Section | Meaning for the review |
| --- | --- |
| CSM signatures missing in FMC | Review adding or correcting these rules in FMC |
| FMC signatures not present in CSM | Review stale or changed rules; never an automatic deletion instruction |
| Same-name objects with different values | CSM expected value, FMC current value, and affected rule IDs on each side |
| Objects referenced only by CSM policy | Check missing references or renamed objects in FMC |
| Objects referenced only by FMC policy | Check stale references or renamed objects |

The inventories cover objects referenced by the selected policies, not the entire servers. An object referenced only on one side may exist unused on the other server. A changed service may produce one missing signature and one extra signature because there is no reliable cross-system rule ID mapping. The tool deliberately does not guess a one-to-one rule edit.

See [the synthetic report](examples/synchronization-report.txt) for a same-name address change, changed HTTPS port, new CSM rule and stale FMC rule. All example addresses and names are invented.

## Four files

| File | Responsibility |
| --- | --- |
| `compare.py` | Configuration, credential prompts, orchestration, directional reports, cleanup |
| `rule.py` | Rule structure, signatures, network/service normalization and object value recording |
| `csm.py` | XML login, complete policy collection and recursive object resolution |
| `fmc.py` | REST login, complete policy collection and recursive object resolution |

There is no class inheritance, transport class, custom exception hierarchy, snapshot system, separate runner or packaging framework. Each reader passes a plain `client` dictionary between functions. Its cache stores API objects; its per-rule inventory records values and lets the report identify affected rules.

## Run

Use Python 3.12+ with Requests from an approved package source:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe compare.py
```

Edit the configuration at the top of `compare.py`: CSM HTTPS URL ending `/nbi`, FMC HTTPS origin, optional FMC domain UUID, trusted CA verification settings, timeout and report directory. Set a CA bundle path where your internal certificate authority requires one. Credentials are entered at runtime; use a normal interactive terminal for hidden password entry.

Imports do not connect or prompt. Reading policies starts only when `main()` runs. No policy changes or deployments are performed. CSM logout is attempted during cleanup; FMC tokens are discarded locally and expire on the server independently.

Text reports are written to a new timestamped file under `reports/`. Real reports contain infrastructure information and must remain private. Exit codes: **0** = match within the selected scope, **1** = drift, **2** = collection/comparison/output failure. Failure must not be interpreted as a match.

## Reliability and boundaries

- Follow policy pagination and check reported totals and repeated IDs. CSM responses without both `endIndex` and `totalCount` on the first page are accepted as unpaginated; completeness cannot be independently verified in that case.
- Stop on unresolved, cyclic, empty or unsupported objects. Never silently substitute Any for a failed object lookup.
- Detect conflicting values for the same named object in collected inventories.
- Requests use a 30-second timeout by default and three attempts for HTTP 429, with a five-second pause. Other HTTP/connection errors stop the run.
- Keep both policies stable during collection. These APIs do not provide an atomic cross-server snapshot; pagination checks and caches cannot detect every concurrent edit.
- Empty policies require manual review. Only TCP, UDP and IP-any services are supported; ICMP and other protocols stop the run. FQDNs and device-specific overrides are unsupported. The CSM path targets shared policies.
- Rule order, action, enabled state, source ports, zones, users and other fields are excluded by design. Duplicate identical rule signatures are compared by presence, not multiplicity. A match is not proof of effective traffic equivalence or approval to migrate.
- Network/service group values are compared as normalized unions, with named nested member inventories. Exact group nesting layout is not compared when the referenced names and all resolved values remain equivalent.

## Validation status

Validation used 27 local logic tests and 10 offline HTTP-response simulation scenarios; all passed. The simulation exercised the existing request construction, XML/JSON parsing, three-page collection, nested object retrieval and comparison without live server connections. It covered matching policies, address/service/group drift, missing and extra rules, interrupted/repeated pages and an unavailable object. Test harnesses remain outside this four-file repository.

API routes were reviewed against Cisco CSM 4.25 and FMC 7.4/7.6 documentation. Synthetic examples are not captured production responses or full schema certification. Actual server-version compatibility still requires sanitized samples or an authorized lab run. Inherited rules are compared when included in the selected policy response; the tool does not independently traverse parent policies.

The CSM parser accepts scalar references/port values and nested `gid`/`portNum` forms. FMC omitted source/destination/service constraints are interpreted as Any; a summary-only rule response is not independently distinguished from a detailed rule with omitted constraints. These are validation boundaries, not guarantees that every incomplete response is detected.

## Collect a small sanitized API sample

Prefer an isolated test policy with invented names and documentation addresses. Do not change production policy merely to create examples. Collect bodies locally inside the authorized environment and share only a reviewed, sanitized copy through an approved channel.

Start with one rule from each system plus the complete definitions of the objects it references. Include a named host/subnet, a network group with a nested member, a TCP/UDP service, and a nested service group where available. Later include an Any rule, a direct literal, a port range/list, and two pagination responses. Record the installed CSM/FMC versions, whether the CSM policy is shared, and the manually expected comparison result. Version information does not require server addresses or domain names.

### FMC

Open `https://<FMC>/api/api-explorer` using an authorized API account and select the correct domain. Use GET operations only. The [Cisco 7.6 API Explorer guide](https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760/About_The_API_Explorer.html) documents access and domain selection; an API login can displace a UI session for the same account.

Under `/api/fmc_config/v1/domain/{domainUUID}`, retrieve:

```text
GET /policy/accesspolicies?expanded=true&limit=2&offset=0
GET /policy/accesspolicies/{policyUUID}/accessrules?expanded=true&limit=2&offset=0
GET /policy/accesspolicies/{policyUUID}/accessrules?expanded=true&limit=2&offset=2
GET /object/hosts/{id}
GET /object/networks/{id}
GET /object/ranges/{id}
GET /object/networkgroups/{id}
GET /object/protocolportobjects/{id}
GET /object/portobjectgroups/{id}
```

Use only object types actually referenced by the sample and fetch nested members too. Save response bodies as JSON. Two pages are useful only when the selected test policy has more than two rules. Preserve the response envelope, `items`, `paging`, object types, IDs and reference relationships after sanitization. Do not export a browser HAR, cookies, a full request session or authentication headers.

### CSM

Use the approved local API client already used for CSM, with a locally held login cookie. The following are read operations despite using POST:

```text
POST /nbi/configservice/getPolicyConfigByName
POST /nbi/configservice/getPolicyObjectByGID
```

For policy retrieval, use a `policyConfigByNameRequest` XML body with `name` and `policyType=DeviceAccessRuleFirewallPolicy`; retain the common request fields required by your installation. For an object, use a `getPolicyObjectByGID` body containing the selected `gid`. Save XML response bodies only. Keep namespaces and wrapper elements.

For pagination, use the returned `endIndex` as the next request's `startIndex`, preserving `totalCount`. Do not change server-wide paging settings just to obtain samples. See the [CSM 4.25 API specification](https://www.cisco.com/c/dam/en/us/td/docs/security/security_management/cisco_security_manager/security_manager/425/API/CSM-API-Spec-v25.pdf), sections 2.2.1, 3.2.8 and 3.2.22. If your policy type differs, report its type before assuming this reader supports it.

Include `sources`, `destinations`, `services`, the related `policyObject` definitions, nested `refGIDs`, and any referenced `portListPolicyObject`. Do not rewrite scalar XML references into nested elements: we need to observe your server's actual shape.

### Sanitize without breaking the example

- Exclude login/logout traffic, passwords, Authorization headers, cookies (`asCookie`), access/refresh tokens and session identifiers. Do not send a client environment export or raw debug log.
- Replace object/policy/user/domain/device names, descriptions, comments and filenames with invented labels. Sanitize hostnames embedded in `links` and metadata too.
- Replace IDs consistently with synthetic IDs of the same format. A reference and its definition must still agree. CSM and FMC IDs need not match each other; corresponding object names should retain their original equality or difference.
- Use IPv4 documentation networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or IPv6 `2001:db8::/32`. Preserve equality, subnet membership, overlaps and intended differences; do not replace every address with the same value. If production subnet relationships are difficult to sanitize, construct a lab example instead.
- Keep XML tag names/JSON keys, namespaces, types, empty-versus-missing fields, array structure and protocol/port relationships. For sensitive custom ports, use consistent synthetic port numbers while preserving ranges and TCP/UDP distinctions.
- Prefer complete responses from a tiny lab policy. If you trim a production response, label it as an excerpt: do not pretend that it is a complete policy or falsify pagination totals. A separate synthetic full fixture can later be built for pagination tests.
- Validate that the sanitized JSON/XML still parses. Search the entire copy for original names, addresses and secret fields, including metadata and links. Keep any original-to-synthetic mapping private. Manual review and organizational release rules still apply; no regex alone guarantees sanitization.

Suggested first delivery: `csm-rule.xml`, `csm-objects.xml`, `fmc-rule.json`, `fmc-objects.json`, and a short note with versions and expected differences. If combining separate responses into one file, clearly mark them as separate responses rather than changing their original envelopes.
