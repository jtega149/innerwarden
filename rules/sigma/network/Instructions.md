Context
The Sigma rule loader at `crates/sensor/src/detectors/sigma_rule.rs` parses YAML rules from `rules/sigma/**/*.yml` and matches them against incoming events. There are currently ~25 Linux rules in `rules/sigma/` covering filesystem persistence, suspicious shell scripts, log tampering, etc.

A common cloud-attack pattern is scraping the cloud instance metadata service (IMDS): `169.254.169.254` for AWS, `169.254.169.254/computeMetadata/` for GCP, `169.254.169.254/metadata/` for Azure. Any process that hits this endpoint is either:

A legitimate cloud-init / monitoring agent (small allowlist)
Or an attacker enumerating cloud credentials
What needs doing
Add a Sigma rule that matches outbound network connections to `169.254.169.254` from processes that aren't on a small allowlist of legit metadata clients. File should live at `rules/sigma/network/lnx_imds_access_from_non_metadata_client.yml` (create the `network/` subdir if needed).

The rule should match the field `destination_ip = 169.254.169.254` AND `process_comm not in [cloud-init, ec2-metadata-collector, instance-controller, gcp-metadata-server, azure-metadata-monitor]` (operator can extend the allowlist via per-host config later).

Severity: Medium. MITRE: T1552.005 (Cloud Instance Metadata API).

Acceptance criteria

New `.yml` file under `rules/sigma/network/`

Conforms to the Sigma format already in use (see existing rules in `rules/sigma/auditd/` for shape).

At least one test fixture in `testdata/` (or wherever existing rules are tested) showing the rule matches a synthetic IMDS-access event.

Doesn't false-positive on the 5-6 legit metadata-client process names.

`cargo test -p innerwarden-sensor sigma` still passes.
Why this is a good first issue
Single YAML file + one test fixture.
Pure detection logic; no plumbing.
Real-world signal: the Capital One breach (2019) and many cloud incidents start with IMDS scraping.
Pointers
Sigma loader: `crates/sensor/src/detectors/sigma_rule.rs`
Existing rules: `rules/sigma/file_event/`, `rules/sigma/auditd/`
MITRE T1552.005: https://attack.mitre.org/techniques/T1552/005/