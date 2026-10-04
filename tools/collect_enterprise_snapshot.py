"""Optional tenant-owned GET-only collection, or credential-free synthetic fixtures."""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise import (  # noqa: E402
    EnterpriseReader,
    parse_entra_user,
    parse_github_members,
    snapshot,
    utc_now,
)
from integrations.errors import ConnectorError  # noqa: E402


def fixture_snapshot(provider, phase):
    path = ROOT / "integrations" / "fixtures" / f"enterprise-{provider}-{phase}.json"
    fixture = json.loads(path.read_text(encoding="utf-8"))
    at = utc_now()
    tenant_id, subject_id = fixture["tenantId"], fixture["subjectId"]
    if provider == "entra":
        observations = [
            parse_entra_user(
                fixture["responses"]["user"],
                tenant_id=tenant_id,
                subject_id=subject_id,
                observed_at=at,
            )
        ]
    else:
        observations = [
            parse_github_members(
                fixture["responses"][endpoint],
                tenant_id=tenant_id,
                subject_id=subject_id,
                capability=capability,
                scope=f"organization:{tenant_id}",
                observed_at=at,
            )
            for capability, endpoint in (
                ("organization_membership", "members"),
                ("outside_collaborator", "outside_collaborators"),
            )
        ]
        observations.append(
            parse_github_members(
                fixture["responses"]["collaborators"],
                tenant_id=tenant_id,
                subject_id=subject_id,
                capability="repository_collaborator",
                scope="repository:434343",
                observed_at=at,
            )
        )
    return snapshot(
        provider,
        tenant_id,
        subject_id,
        observations,
        method="synthetic_fixture",
        collected_at=at,
        limitations=[
            "Synthetic vendor-response fixture only; no tenant was contacted and no access was changed.",
            "Missing GitHub membership remains unknown; account-disabled observations do not prove full closure.",
        ],
    )


def private_output(value, *, fixture):
    original = Path(value).absolute()
    path = original.resolve()
    allowed = (ROOT / ("output" if fixture else ".local") / "enterprise").resolve()
    if not path.is_relative_to(allowed) or path == allowed or path.suffix != ".json":
        raise ConnectorError(
            "Output must be a JSON file inside the documented ignored output directory"
        )
    # Reject existing links, including ancestor junctions, before creating output directories.
    for parent in (original, *original.parents):
        if parent == ROOT.parent:
            break
        if parent.is_symlink() or parent.is_junction():
            raise ConnectorError("Output links and junctions are not supported")
    if path.exists():
        raise ConnectorError("Output already exists; choose a new filename")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("entra", "github"), required=True)
    parser.add_argument("--fixture", choices=("before", "after"))
    parser.add_argument(
        "--tenant-id", help="Stable Entra tenant UUID or GitHub numeric organization ID"
    )
    parser.add_argument("--subject-id", help="Explicit stable mapped user UUID or numeric ID")
    parser.add_argument(
        "--organization", help="GitHub organization slug used only for the API path"
    )
    parser.add_argument(
        "--repository", action="append", default=[], help="Explicit GitHub repository path"
    )
    parser.add_argument(
        "--authorized-read-only-scope",
        action="store_true",
        help="Confirm authorization to collect this exact user-owned tenant scope",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        output = private_output(args.output, fixture=bool(args.fixture))
        if args.fixture:
            if (
                args.tenant_id
                or args.subject_id
                or args.organization
                or args.repository
                or args.authorized_read_only_scope
            ):
                raise ConnectorError("Fixture mode does not accept live scope inputs")
            report = fixture_snapshot(args.provider, args.fixture)
        else:
            if not args.authorized_read_only_scope or not args.tenant_id or not args.subject_id:
                raise ConnectorError(
                    "Explicit tenant, subject, and read-only scope authorization are required"
                )
            if args.provider == "entra" and (args.organization or args.repository):
                raise ConnectorError("GitHub paths cannot be used for Entra collection")
            if args.provider == "github" and not args.organization:
                raise ConnectorError("A GitHub organization path is required")
            token_name = (
                "ACCESSOPS_GRAPH_READ_TOKEN"
                if args.provider == "entra"
                else "ACCESSOPS_GITHUB_READ_TOKEN"
            )
            reader = EnterpriseReader(token=os.environ.get(token_name, ""))
            try:
                report = (
                    reader.entra(tenant_id=args.tenant_id, subject_id=args.subject_id)
                    if args.provider == "entra"
                    else reader.github(
                        tenant_id=args.tenant_id,
                        subject_id=args.subject_id,
                        organization=args.organization,
                        repositories=args.repository,
                    )
                )
            finally:
                reader.close()
        encoded = json.dumps(report, indent=2) + "\n"
        if len(encoded.encode("utf-8")) > 100_000:
            raise ConnectorError("Snapshot exceeds import size bound")
        with output.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
        unknown = sum(item["status"] == "unknown" for item in report["observations"])
        print(
            f"Saved {report['collectionMethod']} snapshot: {len(report['observations'])} observations, {unknown} unknown. No writes performed."
        )
        return 0
    except (ConnectorError, OSError, ValueError, KeyError):
        print(
            "Snapshot collection failed; check scope, private output path, and token configuration. No vendor response or credential is printed.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
