"""Static analysis for Claude plugin marketplace entries and package trees.

Findings come from parsed manifests and executable surfaces, not from issue
titles. A floating Git ref, provider secret, pipe-to-shell installer,
unsigned executable download, package.json lifecycle download, unpinned
package URL install, dynamic eval/exec, undeclared hook, hidden undeclared
executable or config surface, archive path
escape, decompression bomb or nested-archive depth, unadmitted nested
submodule, hardcoded GitHub write token, GitHub merge or release CLI command, Docker
socket bind, host browser-profile store, host cookie or token store,
secret copied into a network request, secret copied into a prompt, log,
or subprocess environment, secret copied into MCP env or args,
a non-standard JSON constant, malformed UTF-8 JSON bytes, a
non-NFC identity name, conflicting plugin/skill/command identity,
undeclared vendored or generated third-party
code, a
description that denies inventoried write, network, GitHub
write, credential, remote MCP, or shell capabilities, or a released
skill-supply-chain finding on a plugin skill/agent surface is a policy
finding. Capability inventory is evidence,
not permission, except that hook or manifest ``gh pr merge`` and
``gh release create|upload|delete|edit`` fail closed as command findings.
Hook or manifest ``kubectl apply`` and ``docker push`` fail closed as
deployment-write command findings. Hook or manifest ``terraform apply``
and ``helm install`` fail closed as infra-write command findings.
Hook or manifest ``vercel deploy`` and ``fly deploy`` fail closed as
hosted-deploy command findings. Hook or manifest ``aws cloudformation
deploy``, ``aws deploy create-deployment``, ``gcloud run|app|functions
deploy``, and ``az webapp deploy`` fail closed as cloud-deploy command
findings. Hook or manifest ``aws s3 sync``, ``aws s3 cp``, and
``az containerapp up`` fail closed as object-store and Container Apps
writes. Hook or manifest ``npm publish``, ``twine upload``, and
``cargo publish`` fail closed as registry-publish command findings.
Hook or manifest ``pnpm publish``, ``uv publish``, and
``poetry publish`` fail closed as alternate-manager registry writes.
Hook or manifest ``gem push`` and ``nuget push`` fail closed as
RubyGems and NuGet registry writes. Hook or manifest ``dart pub
publish``, ``flutter pub publish``, and ``pub publish`` fail closed
as pub.dev registry writes.
Unquoted ``#`` comments and
``echo``/``printf``/``print`` lookalikes are not that class.
``terraform plan``, ``helm list``, ``vercel ls``, ``fly status``,
``aws s3 ls``, ``gcloud config list``, ``az account show``,
``npm pack``, ``cargo check``, ``gem list``, and ``nuget list``
stay inventory. Hook or manifest paths into
``~/.netrc``, ``~/.aws/credentials``,
GitHub CLI hosts, Docker auth ``config.json``, cookie jars, and
``~/.ssh/id_*`` private keys fail closed as credential-store findings.
Chrome and Firefox profile stores stay browser-profile findings.
Hardcoded PATs stay write-token findings.
``gh issue create``, ``gh pr review``, ``kubectl get``, ``docker ps``,
``terraform plan``, ``helm list``, ``vercel ls``, ``fly status``,
``aws s3 ls``, ``gcloud config list``, ``az account show``,
``npm pack``, ``cargo check``, ``gem list``, and ``nuget list``
stay inventory. Skill
homoglyph, injection, exfiltration, and placeholder hits reuse #1036 rule
identities. Skill, command, or agent text that hides tool use, rewrites
the system prompt, or escalates the declared goal is a separate
instruction-override family. Setuid, setgid, or world-writable executable
and hook files fail admission. Zip or tar members whose uncompressed size
divided by compressed size exceeds the bounded ratio, or nested archives
beyond a small depth, fail admission without extracting the payload.
Materialized files and archive members nested beyond a bounded path
component depth fail admission as excessive path depth.
A lockfile-backed package.json without a
lifecycle download stays inventory. Vendored trees are one scope finding,
not hook scans. A first-party ``SHA256SUMS``, ``SHA256SUMS.txt``,
``checksums.sha256``, or ``*.sha256`` next to ``plugin.json`` that names
the plugin artifact or enumerated files fails closed when the digest
disagrees with bytes on disk. Comments are ignored. Absence of a
checksum file is not that class. A checksum file with digest rows and
no non-empty sibling ``.sig``, ``.asc``, ``.gpg``, ``.bundle``, or
``cosign.bundle`` fails closed as an unsigned checksum. Network Cosign
or GPG verification is not performed. Receipts bind
``policy_provenance`` to the running AppGuardrail release and the exact
scan-policy bytes, and ``sbom_sha256`` to a deterministic CycloneDX
document of declared dependencies; verification fails closed when that
digest or scanner version disagrees. ``scan_result=pass`` is not Noema
admission.
"""

from __future__ import annotations

from dataclasses import dataclass
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
from typing import Final, Iterable
import unicodedata
import zipfile

from .claude_plugin_sarif import finding_summary_to_sarif, sarif_document_sha256

CLAUDE_PLUGIN_FLOATING_REF_MESSAGE: Final = (
    "Claude plugin source uses a floating branch or tag instead of an immutable "
    "40-character commit SHA. Pin the exact Git object before admission. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_PROVIDER_SECRET_MESSAGE: Final = (
    "Claude plugin package contains a direct model-provider secret or routing "
    "key. Remove the secret and load credentials from the host secret store. "
    "[CWE-798 - Use of Hard-coded Credentials]"
)
CLAUDE_PLUGIN_PIPE_TO_SHELL_MESSAGE: Final = (
    "Claude plugin hook or package lifecycle script downloads a mutable "
    "script and pipes it to a shell. Pin and verify installers; do not "
    "execute unsigned remote content. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_UNDECLARED_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin package contains an executable surface that is not declared "
    "in the plugin manifest. Unknown hooks fail admission until classified. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)
CLAUDE_PLUGIN_HIDDEN_UNDECLARED_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin package contains a hidden executable or configuration "
    "surface that is not declared in the plugin manifest. Dotfile names and "
    "hidden directories fail admission until classified. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)
CLAUDE_PLUGIN_SYMLINK_ESCAPE_MESSAGE: Final = (
    "Claude plugin package contains a symbolic link. Symlinks are not followed "
    "and fail admission until the exact regular-file identity is declared. "
    "[CWE-59 - Improper Link Resolution Before File Access]"
)
CLAUDE_PLUGIN_DUPLICATE_JSON_MESSAGE: Final = (
    "Claude plugin manifest contains duplicate JSON object members. Duplicate "
    "keys conceal identity and must fail admission. "
    "[CWE-20 - Improper Input Validation]"
)
CLAUDE_PLUGIN_NONSTANDARD_JSON_MESSAGE: Final = (
    "Claude plugin manifest contains a non-standard JSON constant. NaN, "
    "Infinity, and -Infinity are not JSON numbers and must fail admission. "
    "[CWE-20 - Improper Input Validation]"
)
CLAUDE_PLUGIN_NORMALIZED_NAME_MESSAGE: Final = (
    "Claude plugin identity name is not Unicode NFC. Decode and normalize "
    "the declared name before admission so catalog and artifact identities "
    "compare as one object. "
    "[CWE-451 - User Interface (UI) Misrepresentation of Critical Information]"
)
CLAUDE_PLUGIN_CONFLICTING_IDENTITY_MESSAGE: Final = (
    "Claude plugin package declares the same identity name on more than one "
    "plugin, skill, or command surface. Duplicate names conceal which "
    "surface is admitted. "
    "[CWE-451 - User Interface (UI) Misrepresentation of Critical Information]"
)
CLAUDE_PLUGIN_MALFORMED_UTF8_MESSAGE: Final = (
    "Claude plugin manifest is not valid UTF-8. Truncated multibyte "
    "sequences, invalid continuation bytes, and lone surrogates must fail "
    "admission. [CWE-20 - Improper Input Validation]"
)
CLAUDE_PLUGIN_UNBOUNDED_MCP_MESSAGE: Final = (
    "Claude plugin starts a remote or stdio MCP server without a bounded "
    "schema and source or authentication identity. Inventory is not permission. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)
CLAUDE_PLUGIN_LICENSE_MISSING_MESSAGE: Final = (
    "Claude plugin package has no LICENSE or NOTICE file. Record license "
    "evidence without inventing legal approval. "
    "[CWE-1104 - Use of Unmaintained Third Party Components]"
)
CLAUDE_PLUGIN_LICENSE_MISMATCH_MESSAGE: Final = (
    "Claude plugin license evidence names more than one SPDX identifier. "
    "Record the conflict without inventing legal approval. "
    "[CWE-1104 - Use of Unmaintained Third Party Components]"
)
CLAUDE_PLUGIN_CHECKSUM_MISMATCH_MESSAGE: Final = (
    "Claude plugin checksum file lists a SHA-256 digest that does not match "
    "the bytes on disk. Bind admission to the exact artifact. Absence of a "
    "checksum file is not this class. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_UNSIGNED_CHECKSUM_MESSAGE: Final = (
    "Claude plugin checksum file lists digests but has no sibling signature "
    "file. Place a non-empty Cosign bundle or detached GPG signature next "
    "to the checksum. Network verification is not performed. "
    "[CWE-347 - Improper Verification of Cryptographic Signature]"
)
CLAUDE_PLUGIN_DYNAMIC_EVAL_MESSAGE: Final = (
    "Claude plugin hook evaluates a string as code. Dynamic eval, exec, "
    "compile, or Function constructors fail admission. "
    "[CWE-95 - Improper Neutralization of Directives in Dynamically Evaluated Code]"
)
_DYNAMIC_EVAL = re.compile(
    r"\b(?:eval|exec|compile)\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|"
    r"(?:^|[\s;&|])eval\s+[\"'$]",
    re.IGNORECASE | re.MULTILINE,
)
_SPDX_TOKEN = re.compile(
    r"\b(Apache-2\.0|MIT|BSD-2-Clause|BSD-3-Clause|GPL-3\.0-only|"
    r"GPL-3\.0-or-later|LGPL-3\.0-only|AGPL-3\.0-only|MPL-2\.0|ISC|"
    r"Unlicense|CC0-1\.0|0BSD)\b",
    re.IGNORECASE,
)
CLAUDE_PLUGIN_CONCEALED_IDENTITY_MESSAGE: Final = (
    "Claude plugin manifest contains concealed control or bidirectional "
    "formatting characters. Decode identity before admission. "
    "[CWE-451 - User Interface (UI) Misrepresentation of Critical Information]"
)
CLAUDE_PLUGIN_OVERSIZED_PACKAGE_MESSAGE: Final = (
    "Claude plugin package exceeds the bounded file count or scanned byte "
    "budget. Hostile oversized trees fail admission. "
    "[CWE-400 - Uncontrolled Resource Consumption]"
)
CLAUDE_PLUGIN_EXCESSIVE_PATH_DEPTH_MESSAGE: Final = (
    "Claude plugin tree or archive member nests directories beyond the "
    "bounded path depth. Deep recursion fails admission and is not "
    "extracted. "
    "[CWE-400 - Uncontrolled Resource Consumption]"
)
CLAUDE_PLUGIN_DECOMPRESSION_BOMB_MESSAGE: Final = (
    "Claude plugin archive member expands far beyond its compressed size, "
    "nests archives beyond the bounded depth, or the archive's total "
    "uncompressed regular-member bytes exceed the package budget. Do not "
    "extract the payload. "
    "[CWE-409 - Improper Handling of Highly Compressed Data (Data Amplification)]"
)
CLAUDE_PLUGIN_SETUID_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin executable or hook has the setuid or setgid bit. "
    "Privilege-elevating modes fail admission. "
    "[CWE-732 - Incorrect Permission Assignment for Critical Resource]"
)
CLAUDE_PLUGIN_WORLD_WRITABLE_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin executable or hook is world-writable. Tamperable host "
    "modes fail admission. "
    "[CWE-732 - Incorrect Permission Assignment for Critical Resource]"
)
CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE: Final = (
    "Claude plugin marketplace identity does not match the retrieved artifact "
    "ref, repository, or source path. Bind admission to one exact object. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_ARCHIVE_PATH_TRAVERSAL_MESSAGE: Final = (
    "Claude plugin archive contains a member that escapes the extract root. "
    "Do not follow ../, absolute, or Windows-prefix paths. "
    "[CWE-22 - Improper Limitation of a Pathname to a Restricted Directory]"
)
CLAUDE_PLUGIN_UNADMITTED_SUBMODULE_MESSAGE: Final = (
    "Claude plugin nested submodule, gitlink, or .gitmodules pointer lacks a "
    "recursively admitted immutable SHA identity. Pin and scan the nested "
    "package before admission. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_GITHUB_WRITE_TOKEN_MESSAGE: Final = (
    "Claude plugin package contains a hardcoded GitHub personal or app token. "
    "That token is write-capable authority. Remove it and use the host secret "
    "store. [CWE-798 - Use of Hard-coded Credentials]"
)
CLAUDE_PLUGIN_GITHUB_MERGE_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs GitHub CLI merge. Merging a pull "
    "request is write authority on the default branch. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_GITHUB_RELEASE_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs GitHub CLI release create, upload, "
    "delete, or edit. Publishing a release is write authority. Remove the "
    "command. [CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_KUBECTL_APPLY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs kubectl apply. Applying manifests "
    "is write authority on a cluster. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_DOCKER_PUSH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs docker push. Pushing an image is "
    "write authority on a registry. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_TERRAFORM_APPLY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs terraform apply. Applying "
    "infrastructure is write authority. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_HELM_INSTALL_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs helm install. Installing a chart "
    "is write authority on a cluster. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_VERCEL_DEPLOY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs vercel deploy. Publishing to a "
    "hosted platform is write authority. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_FLY_DEPLOY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs fly deploy. Publishing to a "
    "hosted platform is write authority. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_AWS_DEPLOY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs AWS deploy writes. CloudFormation "
    "deploy and CodeDeploy create-deployment are write authority. Remove "
    "the command. [CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_GCLOUD_DEPLOY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs gcloud deploy. Publishing Cloud "
    "Run, App Engine, or Functions is write authority. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_AZ_DEPLOY_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs az webapp deploy. Publishing an "
    "Azure web app is write authority. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_AWS_S3_WRITE_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs aws s3 sync or aws s3 cp. "
    "Copying objects into a bucket is write authority. Remove the "
    "command. [CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_AZ_CONTAINERAPP_UP_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs az containerapp up. Publishing "
    "a Container Apps revision is write authority. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_NPM_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs npm publish. Publishing a package "
    "is write authority on the npm registry. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_PYPI_UPLOAD_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs twine upload. Uploading a "
    "distribution is write authority on PyPI. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_CARGO_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs cargo publish. Publishing a crate "
    "is write authority on crates.io. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_PNPM_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs pnpm publish. Publishing a "
    "package is write authority on the npm registry. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_UV_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs uv publish. Publishing a "
    "distribution is write authority on PyPI. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_POETRY_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs poetry publish. Publishing a "
    "distribution is write authority on PyPI. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_GEM_PUSH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs gem push. Publishing a gem is "
    "write authority on RubyGems. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_NUGET_PUSH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs nuget push. Publishing a package "
    "is write authority on NuGet. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_PUB_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs dart pub publish. Publishing a "
    "package is write authority on pub.dev. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_HEX_PUBLISH_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs hex publish. Publishing a "
    "package is write authority on Hex.pm. Remove the command. "
    "[CWE-269 - Improper Privilege Management]"
)
CLAUDE_PLUGIN_CONDA_UPLOAD_COMMAND_MESSAGE: Final = (
    "Claude plugin hook or manifest runs conda upload. Publishing a "
    "package is write authority on Anaconda.org. Remove the command. "
    "[CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_DOCKER_SOCKET_MESSAGE: Final = (
    "Claude plugin hook reaches the host Docker socket. Socket access is host "
    "control, not an image push. Remove the socket bind and keep builds "
    "isolated. [CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_BROWSER_PROFILE_MESSAGE: Final = (
    "Claude plugin hook or manifest reaches a host browser profile store. "
    "Cookie and login databases are credential access, not a supported "
    "browser. Remove the profile path. "
    "[CWE-219 - Sensitive Information in Browser's History/Cache/Cookies]"
)
CLAUDE_PLUGIN_CREDENTIAL_STORE_MESSAGE: Final = (
    "Claude plugin hook or manifest reaches a host cookie or token store. "
    "Netrc, cloud credentials, GitHub CLI hosts, Docker registry auth, "
    "cookie jars, and SSH private keys are credential access, not browser "
    "profile stores. Remove the store path. "
    "[CWE-522 - Insufficiently Protected Credentials]"
)
CLAUDE_PLUGIN_DECEPTIVE_DESCRIPTION_MESSAGE: Final = (
    "Claude plugin, skill, or command description claims innocuous, "
    "read-only, or local-only behavior while the capability inventory "
    "shows write, network, GitHub write, credential, remote MCP, or "
    "shell access that the description denies. Inventory is evidence, "
    "not permission; the description must not contradict it. "
    "[CWE-451 - User Interface (UI) Misrepresentation of Critical Information]"
)
CLAUDE_PLUGIN_SECRET_TO_NETWORK_MESSAGE: Final = (
    "Claude plugin hook copies a named secret into a network request. Keep "
    "credentials out of curl, wget, and fetch payloads. "
    "[CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor]"
)
CLAUDE_PLUGIN_SECRET_TO_PROMPT_MESSAGE: Final = (
    "Claude plugin hook copies a named secret into a prompt, log, or "
    "subprocess environment. Keep credentials out of prompt files, logs, "
    "and child process env dicts. "
    "[CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor]"
)
CLAUDE_PLUGIN_SECRET_TO_MCP_MESSAGE: Final = (
    "Claude plugin copies a named secret into an MCP server env, args, or "
    "command. Keep credentials out of MCP declarations. "
    "[CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor]"
)
CLAUDE_PLUGIN_HIDE_ACTIONS_MESSAGE: Final = (
    "Claude plugin skill, command, or agent text instructs the model to hide "
    "tool use or conceal actions from the user. Instruction text is untrusted "
    "data. Remove the directive. "
    "[CWE-451 - User Interface (UI) Misrepresentation of Critical Information]"
)
CLAUDE_PLUGIN_SELF_MODIFY_MESSAGE: Final = (
    "Claude plugin skill, command, or agent text instructs the model to "
    "rewrite its system prompt or ignore previous policy. Instruction text "
    "is untrusted data. Remove the directive. "
    "[CWE-693 - Protection Mechanism Failure]"
)
CLAUDE_PLUGIN_GOAL_ESCALATION_MESSAGE: Final = (
    "Claude plugin skill, command, or agent text instructs the model to "
    "expand or escalate the goal beyond the declared task. Instruction text "
    "is untrusted data. Remove the directive. "
    "[CWE-693 - Protection Mechanism Failure]"
)
CLAUDE_PLUGIN_UNSIGNED_EXECUTABLE_DOWNLOAD_MESSAGE: Final = (
    "Claude plugin hook or package lifecycle script downloads an unsigned "
    "executable and makes it runnable. Pin and verify binaries; do not "
    "fetch mutable runtime payloads. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_UNPINNED_PACKAGE_INSTALL_MESSAGE: Final = (
    "Claude plugin hook or package lifecycle script installs a package "
    "from an unpinned URL. Pin versions and integrity hashes; do not "
    "install mutable remote artifacts. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_VENDORED_SCOPE_MESSAGE: Final = (
    "Claude plugin package contains vendored or generated third-party code "
    "that is not declared as a bounded, identity-bound dependency. "
    "Admission cannot treat vendor/, node_modules/, dist/, or min.js "
    "copies as first-party hooks. Declare the exact path in files[] "
    "or omit the checked-in copy. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)
_MCP_FILENAMES: Final = frozenset({".mcp.json", "mcp.json"})
_CHECKSUM_FILENAMES: Final = frozenset(
    {"SHA256SUMS", "SHA256SUMS.txt", "checksums.sha256"}
)
_SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_PACKAGE_FILES: Final = 10_000
_MAX_PACKAGE_BYTES: Final = 10 * 1024 * 1024
_MAX_ARCHIVE_COMPRESSION_RATIO: Final = 100
_MAX_ARCHIVE_NESTING_DEPTH: Final = 1
_MAX_PATH_DEPTH: Final = 32
_CONCEALED_CHAR = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200d\u202a-\u202e\u2066-\u2069]"
)
_SCANNER_NAME: Final = "appguardrail"
_SCANNER_VERSION: Final = "0.1.1"
_POLICY_PROVENANCE_SCHEMA_VERSION: Final = "1"
_SCANNER_SOURCE_REPOSITORY: Final = "ContextualWisdomLab/appguardrail"

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_ARCHIVE_SUFFIXES: Final = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")
_PROVIDER_SECRET = re.compile(
    r"\b(?:OPENAI_API_KEY|NVIDIA_NIM_API_KEY(?:_SUB)?|BYTEZ_API_KEY|"
    r"OPENROUTER_API_KEY)\b"
)
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh|zsh)\b",
    re.IGNORECASE,
)
_GITHUB_TOKEN = re.compile(
    r"\b(?P<prefix>ghp_|github_pat_|gho_|ghu_|ghs_)[A-Za-z0-9_]{20,}\b"
)
_GITHUB_MERGE_COMMAND = re.compile(r"\bgh\s+pr\s+merge\b", re.IGNORECASE)
_GITHUB_RELEASE_COMMAND = re.compile(
    r"\bgh\s+release\s+(?P<verb>create|upload|delete|edit)\b",
    re.IGNORECASE,
)
_KUBECTL_APPLY_COMMAND = re.compile(r"\bkubectl\s+apply\b", re.IGNORECASE)
_DOCKER_PUSH_COMMAND = re.compile(
    r"\bdocker(?:\s+image)?\s+push\b",
    re.IGNORECASE,
)
_TERRAFORM_APPLY_COMMAND = re.compile(r"\bterraform\s+apply\b", re.IGNORECASE)
_HELM_INSTALL_COMMAND = re.compile(r"\bhelm\s+install\b", re.IGNORECASE)
_VERCEL_DEPLOY_COMMAND = re.compile(r"\bvercel\s+deploy\b", re.IGNORECASE)
_FLY_DEPLOY_COMMAND = re.compile(r"\b(?:fly|flyctl)\s+deploy\b", re.IGNORECASE)
_AWS_DEPLOY_COMMAND = re.compile(
    r"\baws\s+(?:cloudformation\s+deploy|deploy\s+create-deployment)\b",
    re.IGNORECASE,
)
_GCLOUD_DEPLOY_COMMAND = re.compile(
    r"\bgcloud\s+(?P<service>run|app|functions)\s+deploy\b",
    re.IGNORECASE,
)
_AZ_DEPLOY_COMMAND = re.compile(r"\baz\s+webapp\s+deploy\b", re.IGNORECASE)
_AWS_S3_WRITE_COMMAND = re.compile(r"\baws\s+s3\s+(?P<verb>sync|cp)\b", re.IGNORECASE)
_AZ_CONTAINERAPP_UP_COMMAND = re.compile(
    r"\baz\s+containerapp\s+up\b",
    re.IGNORECASE,
)
_NPM_PUBLISH_COMMAND = re.compile(r"\bnpm\s+publish\b", re.IGNORECASE)
_PYPI_UPLOAD_COMMAND = re.compile(r"\btwine\s+upload\b", re.IGNORECASE)
_CARGO_PUBLISH_COMMAND = re.compile(r"\bcargo\s+publish\b", re.IGNORECASE)
_PNPM_PUBLISH_COMMAND = re.compile(r"\bpnpm\s+publish\b", re.IGNORECASE)
_UV_PUBLISH_COMMAND = re.compile(r"\buv\s+publish\b", re.IGNORECASE)
_POETRY_PUBLISH_COMMAND = re.compile(r"\bpoetry\s+publish\b", re.IGNORECASE)
_GEM_PUSH_COMMAND = re.compile(r"\bgem\s+push\b", re.IGNORECASE)
_NUGET_PUSH_COMMAND = re.compile(
    r"\b(?:dotnet\s+)?nuget\s+push\b",
    re.IGNORECASE,
)
_PUB_PUBLISH_COMMAND = re.compile(
    r"\b(?:(?P<sdk>dart|flutter)\s+)?pub\s+publish\b",
    re.IGNORECASE,
)
_HEX_PUBLISH_COMMAND = re.compile(
    r"\b(?:mix\s+hex\.publish|hex\s+publish)\b",
    re.IGNORECASE,
)
_CONDA_UPLOAD_COMMAND = re.compile(
    r"\b(?P<cli>conda|anaconda)\s+upload\b",
    re.IGNORECASE,
)
_REPORTING_BUILTINS: Final = frozenset({"echo", "printf", "print"})
_FIRST_SHELL_TOKEN = re.compile(r"\s*([A-Za-z0-9_./+-]+)")
_DOCKER_SOCKET = re.compile(
    r"(?:/var/run/docker\.sock|unix://\S*docker\.sock)",
    re.IGNORECASE,
)
_BROWSER_PROFILE = re.compile(
    r"(?:Google/Chrome|Chromium/User Data|"
    r"%LOCALAPPDATA%\\Google\\Chrome|"
    r"Library/Application Support/(?:Google/Chrome|Chromium)|"
    r"\.mozilla/firefox|cookies\.sqlite|Login Data)",
    re.IGNORECASE,
)
_CREDENTIAL_STORE_PATTERNS: Final = (
    (re.compile(r"(?:~[/\\])?\.netrc\b|_netrc\b", re.IGNORECASE), "~/.netrc"),
    (
        re.compile(r"(?:~[/\\])?\.aws[/\\]credentials\b", re.IGNORECASE),
        "~/.aws/credentials",
    ),
    (
        re.compile(r"(?:~[/\\])?\.config[/\\]gh[/\\]hosts\.ya?ml\b", re.IGNORECASE),
        "~/.config/gh/hosts.yml",
    ),
    (
        re.compile(r"(?:~[/\\])?\.docker[/\\]config\.json\b", re.IGNORECASE),
        "~/.docker/config.json",
    ),
    (
        re.compile(r"(?:~[/\\])?\.curl_home\b", re.IGNORECASE),
        "~/.curl_home",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9._-])cookies\.txt\b", re.IGNORECASE),
        "cookies.txt",
    ),
    (
        re.compile(
            r"(?:~[/\\])?\.ssh[/\\](?P<name>id_[A-Za-z0-9_]+)(?![A-Za-z0-9_.])",
            re.IGNORECASE,
        ),
        "",
    ),
)
_CREDENTIAL_STORE = re.compile(
    "|".join(pattern.pattern for pattern, _label in _CREDENTIAL_STORE_PATTERNS),
    re.IGNORECASE,
)
_SECRET_TO_NETWORK = re.compile(
    r"(?:curl|wget|fetch)\b[^\n]*\$(?:\{)?(?P<name>"
    r"OPENAI_API_KEY|NVIDIA_NIM_API_KEY(?:_SUB)?|BYTEZ_API_KEY|"
    r"OPENROUTER_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|"
    r"AWS_SECRET_ACCESS_KEY)(?:\})?",
    re.IGNORECASE,
)
_NAMED_SECRET_NAMES: Final = (
    r"OPENAI_API_KEY|NVIDIA_NIM_API_KEY(?:_SUB)?|BYTEZ_API_KEY|"
    r"OPENROUTER_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|"
    r"AWS_SECRET_ACCESS_KEY"
)
_NAMED_SECRET_TOKEN = re.compile(_NAMED_SECRET_NAMES, re.IGNORECASE)
_SECRET_REF = re.compile(
    r"(?:\$(?:\{)?"
    + _NAMED_SECRET_NAMES
    + r"(?:\})?|"
    r"os\.environ\s*\[\s*['\"](?:"
    + _NAMED_SECRET_NAMES
    + r")['\"]\s*\]|"
    r"os\.environ\.get\s*\(\s*['\"](?:"
    + _NAMED_SECRET_NAMES
    + r")['\"]|"
    r"os\.getenv\s*\(\s*['\"](?:"
    + _NAMED_SECRET_NAMES
    + r")['\"])",
    re.IGNORECASE,
)
_PROMPT_LOG_SINK = re.compile(
    r"\b(?:echo|printf|print|logging\.\w+|logger\.\w+|"
    r"write_text|write_bytes|\.write|subprocess\.\w+)\b",
    re.IGNORECASE,
)
_SECRET_LOG_IDENT = re.compile(
    r"(?:logging|logger)\.\w+\(\s*(?:api_key|secret|token|password)\s*\)",
    re.IGNORECASE,
)
_SUBPROCESS_SECRET_ENV = re.compile(
    r"subprocess\.\w+\([^;\n]*\benv\s*=\s*\{[^}\n]*(?:"
    + _NAMED_SECRET_NAMES
    + r"|os\.environ\s*\[|:\s*(?:secret|api_key|token)\b)",
    re.IGNORECASE,
)
_PIPE_TO_INTERPRETER = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:python3?|node|nodejs|perl|ruby|pwsh|"
    r"powershell)\b",
    re.IGNORECASE,
)
_DOWNLOAD_TO_FILE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?(?:\s|^)(?:-o|-O|--output-document|--output)\s+"
    r"(?P<path>[^\s;|&]+)",
    re.IGNORECASE,
)
_CHMOD_PLUS_X = re.compile(
    r"\bchmod\s+(?:\+x|a\+x|u\+x)\s+(?P<path>[^\s;|&]+)",
    re.IGNORECASE,
)
_UNPINNED_PACKAGE_INSTALL = re.compile(
    r"\b(?:pip(?:3)?|python(?:3)?\s+-m\s+pip|npm|pnpm|yarn|uv(?:\s+pip)?|"
    r"cargo)\s+(?:install|add)\s+[^\n]*?(?:https?://|git\+https?://|git://)",
    re.IGNORECASE,
)
_SK_LITERAL = re.compile(r"sk-[A-Za-z0-9_-]+")
_PACKAGE_LOCK_NAMES: Final = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
)
_LIFECYCLE_SCRIPT_NAMES: Final = ("preinstall", "install", "postinstall")
_EXECUTABLE_SUFFIXES = frozenset(
    {".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".py"}
)
_SHELL_SUFFIXES: Final = frozenset({".sh", ".bash", ".zsh"})
_HOOK_DIRS = ("hooks", "scripts", "commands")
_VENDORED_SCOPE_DIR_NAMES: Final = frozenset({"vendor", "node_modules", "dist"})
_HIDDEN_CONFIG_SUFFIXES: Final = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env"}
)
_GIT_METADATA_NAMES: Final = frozenset(
    {".gitignore", ".gitattributes", ".gitmodules"}
)
_CLAUDE_PLUGIN_MANIFEST_NAMES: Final = frozenset(
    {"plugin.json", "marketplace.json"}
)
_SKILL_SUPPLY_CHAIN_RULE_IDS: Final = frozenset(
    {
        "skill-name-homoglyph-confusable",
        "skill-manifest-prompt-injection-payload",
        "skill-doc-exfiltration-endpoint-directive",
        "skill-placeholder-template-unresolved",
    }
)
_SKILL_SURFACE_NAMES: Final = frozenset({"SKILL.md", "skill.json", "agent.md"})
_SKILL_MARKDOWN_DIRS: Final = frozenset({"commands", "agents"})
_HIDE_ACTIONS_DIRECTIVE = re.compile(
    r"(?i)(?:do not tell the user[^\n]{0,80}(?:calling tools|tool calls|"
    r"tool use)|hide (?:your )?(?:actions|tool use|tool calls))"
)
_SELF_MODIFY_DIRECTIVE = re.compile(
    r"(?i)(?:ignore previous policy|rewrite (?:your )?system prompt)"
)
_GOAL_ESCALATION_DIRECTIVE = re.compile(
    r"(?i)(?:expand|escalate|broaden) (?:the |your )?(?:goal|scope|objective)"
)
_INSTRUCTION_OVERRIDE_RULES: Final = (
    (
        "claude-plugin-hide-actions-directive",
        _HIDE_ACTIONS_DIRECTIVE,
        CLAUDE_PLUGIN_HIDE_ACTIONS_MESSAGE,
    ),
    (
        "claude-plugin-self-modify-directive",
        _SELF_MODIFY_DIRECTIVE,
        CLAUDE_PLUGIN_SELF_MODIFY_MESSAGE,
    ),
    (
        "claude-plugin-goal-escalation-directive",
        _GOAL_ESCALATION_DIRECTIVE,
        CLAUDE_PLUGIN_GOAL_ESCALATION_MESSAGE,
    ),
)
_DESCRIPTION_JSON_NAMES: Final = frozenset(
    {"plugin.json", "marketplace.json", "skill.json"}
)
_DESCRIPTION_MARKDOWN_DIRS: Final = ("/skills/", "/commands/")
_FRONTMATTER = re.compile(
    r"\A---\r?\n(?P<body>.*?)\r?\n---(?:\r?\n|\Z)",
    re.DOTALL,
)
_READ_ONLY_CLAIM = re.compile(
    r"read[\s-]*only|never writes|does not write|no writes?\b|without writing",
    re.IGNORECASE,
)
_LOCAL_ONLY_CLAIM = re.compile(
    r"local[\s-]*only|\blocal helper\b|\boffline\b|no network|"
    r"never sends|does not send|without network|air[\s-]*gapped|"
    r"no internet|does not access the network",
    re.IGNORECASE,
)
_INNOCUOUS_CLAIM = re.compile(r"\binnocuous\b|\bharmless\b", re.IGNORECASE)
_NO_CREDENTIAL_CLAIM = re.compile(
    r"no credentials?|never (?:reads|accesses) credentials?|"
    r"does not access credentials?|without credentials?|no secrets?",
    re.IGNORECASE,
)
_NO_SHELL_CLAIM = re.compile(
    r"no shell|never executes|does not execute|without executing|"
    r"no command execution",
    re.IGNORECASE,
)
_INVENTORY_MANIFESTS: Final = frozenset(
    {"plugin.json", "marketplace.json", ".mcp.json", "mcp.json", "hooks.json"}
)
CAPABILITY_INVENTORY_KEYS: Final = (
    "browser_profile_access",
    "credential_access",
    "deployment_write",
    "filesystem_read",
    "filesystem_write",
    "github_merge",
    "github_read",
    "github_release",
    "github_review",
    "github_write",
    "mcp_remote_connect",
    "mcp_server_start",
    "model_provider_access",
    "network_egress",
    "package_install",
    "process_spawn",
    "shell_execution",
)
_TEXT_CAPABILITY_PATTERNS: Final = (
    (
        "browser_profile_access",
        re.compile(
            r"Google/Chrome|Chromium|Firefox|cookies\.sqlite|Login Data",
            re.IGNORECASE,
        ),
    ),
    ("credential_access", _PROVIDER_SECRET),
    ("credential_access", _CREDENTIAL_STORE),
    (
        "deployment_write",
        re.compile(
            r"\b(?:kubectl\s+apply|terraform\s+apply|helm\s+install|"
            r"vercel\s+deploy|fly(?:ctl)?\s+deploy|docker\s+push|"
            r"aws\s+(?:cloudformation\s+deploy|deploy\s+create-deployment|s3\s+(?:sync|cp))|"
            r"gcloud\s+(?:run|app|functions)\s+deploy|az\s+webapp\s+deploy|"
            r"az\s+containerapp\s+up)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "filesystem_read",
        re.compile(r"\b(?:cat|read_text|read_bytes|Get-Content)\b"),
    ),
    (
        "filesystem_write",
        re.compile(
            r"\b(?:write_text|write_bytes|mkdir)\b|(?:^|\s)>\s*\S",
            re.MULTILINE,
        ),
    ),
    ("github_merge", re.compile(r"\bgh\s+pr\s+merge\b", re.IGNORECASE)),
    (
        "github_read",
        re.compile(
            r"\bgh\s+(?:api|issue\s+list|pr\s+view|repo\s+view)\b",
            re.IGNORECASE,
        ),
    ),
    ("github_release", re.compile(r"\bgh\s+release\b", re.IGNORECASE)),
    ("github_review", re.compile(r"\bgh\s+pr\s+review\b", re.IGNORECASE)),
    (
        "github_write",
        re.compile(
            r"\bgh\s+(?:issue\s+create|pr\s+create|repo\s+create)\b|"
            r"\b(?:ghp_|github_pat_|gho_|ghu_|ghs_)[A-Za-z0-9_]{20,}\b",
            re.IGNORECASE,
        ),
    ),
    ("model_provider_access", _PROVIDER_SECRET),
    (
        "network_egress",
        re.compile(r"\b(?:curl|wget|fetch)\b|https?://", re.IGNORECASE),
    ),
    (
        "package_install",
        re.compile(
            r"\b(?:pip|npm|pnpm|yarn|uv|cargo|apt-get)\s+install\b|"
            r"\b(?:npm\s+publish|pnpm\s+publish|twine\s+upload|cargo\s+publish|"
            r"uv\s+publish|poetry\s+publish|gem\s+push|"
            r"(?:dotnet\s+)?nuget\s+push|"
            r"(?:dart\s+|flutter\s+)?pub\s+publish|"
            r"mix\s+hex\.publish|hex\s+publish|"
            r"(?:conda|anaconda)\s+upload)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "process_spawn",
        re.compile(r"\b(?:subprocess|os\.system|Popen|posix_spawn)\b"),
    ),
    (
        "shell_execution",
        re.compile(
            r"^#![^\n]*(?:ba)?sh\b|\b(?:bash|zsh)\s+-c\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class PluginHit:
    """One source-bound Claude plugin policy finding."""

    rule_id: str
    line: int
    snippet: str
    message: str
    file: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
    """Bounded binding of one scan to the AppGuardrail release and policy bytes.

    This is not an SPDX SBOM and is not Noema admission. Fields never contain
    secrets, tokens, or unbounded plugin text.
    """

    schema_version: str
    source_repository: str
    scanner_release_version: str
    scanner_policy_sha256: str

    def as_dict(self) -> dict[str, str]:
        """Return JSON-safe provenance without secret literals."""
        return {
            "schema_version": self.schema_version,
            "source_repository": self.source_repository,
            "scanner_release_version": self.scanner_release_version,
            "scanner_policy_sha256": self.scanner_policy_sha256,
        }


@dataclass(frozen=True, slots=True)
class PluginScanReceipt:
    """Bounded deterministic receipt for one Claude plugin artifact scan."""

    scan_receipt_id: str
    scanner_name: str
    scanner_version: str
    scanner_policy_sha256: str
    policy_provenance: PolicyProvenance
    catalog_repository: str
    catalog_commit_sha: str
    marketplace_blob_sha: str
    marketplace_entry_sha256: str
    plugin_name: str
    plugin_version: str
    source_repository: str
    source_commit_sha: str
    source_path: str
    artifact_sha256: str
    file_count: int
    scanned_byte_count: int
    capability_inventory_sha256: str
    sarif_sha256: str
    sbom_sha256: str
    finding_summary: tuple[str, ...]
    license_evidence_summary: str
    scan_started_at: str
    scan_completed_at: str
    scan_result: str

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe receipt with no secret literals."""
        return {
            "scan_receipt_id": self.scan_receipt_id,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scanner_policy_sha256": self.scanner_policy_sha256,
            "policy_provenance": self.policy_provenance.as_dict(),
            "catalog_repository": self.catalog_repository,
            "catalog_commit_sha": self.catalog_commit_sha,
            "marketplace_blob_sha": self.marketplace_blob_sha,
            "marketplace_entry_sha256": self.marketplace_entry_sha256,
            "plugin_name": self.plugin_name,
            "plugin_version": self.plugin_version,
            "source_repository": self.source_repository,
            "source_commit_sha": self.source_commit_sha,
            "source_path": self.source_path,
            "artifact_sha256": self.artifact_sha256,
            "file_count": self.file_count,
            "scanned_byte_count": self.scanned_byte_count,
            "capability_inventory_sha256": self.capability_inventory_sha256,
            "sarif_sha256": self.sarif_sha256,
            "sbom_sha256": self.sbom_sha256,
            "finding_summary": list(self.finding_summary),
            "license_evidence_summary": self.license_evidence_summary,
            "scan_started_at": self.scan_started_at,
            "scan_completed_at": self.scan_completed_at,
            "scan_result": self.scan_result,
        }


def inventory_claude_plugin_capabilities(root: Path) -> dict[str, bool]:
    """Return a machine-readable capability inventory for one plugin tree.

    Inventory is evidence, not permission. A true capability is not a policy
    finding by itself and does not authorize admission or activation.

    Args:
        root: Materialized plugin tree.

    Returns:
        Mapping of every inventory key to a boolean, in deterministic key
        order. Secret literals never appear in the mapping.
    """
    inventory = _empty_capability_inventory()
    texts: list[str] = []
    saw_package_json = False
    saw_lockfile = False
    for path in _walk_entries(root):
        if path.is_symlink():
            continue
        if path.name == "package.json":
            saw_package_json = True
        elif path.name in _PACKAGE_LOCK_NAMES:
            saw_lockfile = True
        suffix = path.suffix.lower()
        if suffix in _SHELL_SUFFIXES:
            inventory["shell_execution"] = True
            inventory["process_spawn"] = True
        elif suffix in _EXECUTABLE_SUFFIXES:
            inventory["process_spawn"] = True
        payload = _regular_file_bytes(path)
        if not payload:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        texts.append(text)
        if path.name in _INVENTORY_MANIFESTS:
            _inventory_manifest_capabilities(text, inventory)
    _inventory_text_capabilities("\n".join(texts), inventory)
    if saw_package_json and saw_lockfile:
        inventory["package_install"] = True
    return {key: inventory[key] for key in CAPABILITY_INVENTORY_KEYS}


def inspect_claude_plugin_file(
    filename: str,
    relative_path: str,
    content: str,
) -> tuple[PluginHit, ...]:
    """Inspect one file for Claude plugin supply-chain findings.

    Args:
        filename: Basename of the file being scanned.
        relative_path: Repository-relative display path.
        content: File text.

    Returns:
        Zero or more hits. Unrelated files return an empty tuple.
        ``package.json`` is inspected only for npm install lifecycle scripts.
    """
    posix = relative_path.replace("\\", "/")
    hits: list[PluginHit] = []
    manifest = _is_manifest(filename, posix)
    hook_surface = _is_hook_surface(filename, posix)
    lifecycle_surface = _is_package_lifecycle_surface(filename)
    if not manifest and not hook_surface and not lifecycle_surface:
        return ()
    if manifest:
        hits.extend(_inspect_manifest(content))
    if _PIPE_TO_SHELL.search(content) and hook_surface:
        match = _PIPE_TO_SHELL.search(content)
        line = 1
        snippet = content.splitlines()[0][:120] if content else filename
        if match is not None:
            line = content[: match.start()].count("\n") + 1
            snippet = content[match.start() :].splitlines()[0].strip()[:120]
        hits.append(
            PluginHit(
                rule_id="claude-plugin-pipe-to-shell",
                line=line,
                snippet=snippet,
                message=CLAUDE_PLUGIN_PIPE_TO_SHELL_MESSAGE,
            )
        )
    if hook_surface:
        hits.extend(_unsigned_executable_download_hits(content))
        hits.extend(_unpinned_package_install_hits(content))
        hits.extend(_dynamic_eval_hits(content))
    if lifecycle_surface:
        hits.extend(_package_lifecycle_hits(content))
    if manifest or hook_surface:
        hits.extend(_github_write_token_hits(content))
        hits.extend(_github_merge_command_hits(content))
        hits.extend(_github_release_command_hits(content))
        hits.extend(_kubectl_apply_command_hits(content))
        hits.extend(_docker_push_command_hits(content))
        hits.extend(_terraform_apply_command_hits(content, manifest=manifest))
        hits.extend(_helm_install_command_hits(content, manifest=manifest))
        hits.extend(_vercel_deploy_command_hits(content, manifest=manifest))
        hits.extend(_fly_deploy_command_hits(content, manifest=manifest))
        hits.extend(_aws_deploy_command_hits(content, manifest=manifest))
        hits.extend(_gcloud_deploy_command_hits(content, manifest=manifest))
        hits.extend(_az_deploy_command_hits(content, manifest=manifest))
        hits.extend(_aws_s3_write_command_hits(content, manifest=manifest))
        hits.extend(_az_containerapp_up_command_hits(content, manifest=manifest))
        hits.extend(_npm_publish_command_hits(content, manifest=manifest))
        hits.extend(_pypi_upload_command_hits(content, manifest=manifest))
        hits.extend(_cargo_publish_command_hits(content, manifest=manifest))
        hits.extend(_pnpm_publish_command_hits(content, manifest=manifest))
        hits.extend(_uv_publish_command_hits(content, manifest=manifest))
        hits.extend(_poetry_publish_command_hits(content, manifest=manifest))
        hits.extend(_gem_push_command_hits(content, manifest=manifest))
        hits.extend(_nuget_push_command_hits(content, manifest=manifest))
        hits.extend(_pub_publish_command_hits(content, manifest=manifest))
        hits.extend(_hex_publish_command_hits(content, manifest=manifest))
        hits.extend(_conda_upload_command_hits(content, manifest=manifest))
        hits.extend(_docker_socket_hits(content))
        hits.extend(_browser_profile_hits(content))
        hits.extend(_credential_store_hits(content))
        hits.extend(_secret_to_network_hits(content))
        hits.extend(_secret_to_prompt_hits(content))
    return tuple(hits)


def inspect_claude_plugin_bytes(
    filename: str,
    relative_path: str,
    payload: bytes,
) -> tuple[PluginHit, ...]:
    """Inspect one file's exact bytes for Claude plugin supply-chain findings.

    Marketplace, plugin, and MCP JSON that is not valid UTF-8 fails closed
    as ``claude-plugin-malformed-utf8``. Snippets are short labels and never
    include the raw invalid bytes. Other surfaces decode when possible;
    invalid UTF-8 on those surfaces is not this class.

    Args:
        filename: Basename of the file being scanned.
        relative_path: Repository-relative display path.
        payload: Exact file bytes.

    Returns:
        Zero or more hits. Unrelated files return an empty tuple.
    """
    posix = relative_path.replace("\\", "/")
    if _is_manifest(filename, posix):
        label = _malformed_utf8_label(payload)
        if label is not None:
            return (
                PluginHit(
                    rule_id="claude-plugin-malformed-utf8",
                    line=1,
                    snippet=label,
                    message=CLAUDE_PLUGIN_MALFORMED_UTF8_MESSAGE,
                ),
            )
        content = payload.decode("utf-8")
    else:
        try:
            content = payload.decode("utf-8")
        except UnicodeDecodeError:
            content = ""
    return inspect_claude_plugin_file(filename, relative_path, content)


def _malformed_utf8_label(payload: bytes) -> str | None:
    """Return a short invalid-UTF-8 label, or ``None`` when bytes are valid UTF-8.

    Args:
        payload: Exact file bytes.

    Returns:
        ``truncated-utf8``, ``invalid-continuation``, ``lone-surrogate``, or
        ``invalid-utf8`` when the bytes are not well-formed UTF-8. Valid UTF-8
        including CJK returns ``None``.
    """
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        try:
            payload.decode("utf-8", "surrogatepass")
        except UnicodeDecodeError:
            reason = exc.reason
            if "unexpected end of data" in reason:
                return "truncated-utf8"
            if "invalid continuation" in reason:
                return "invalid-continuation"
            return "invalid-utf8"
        return "lone-surrogate"
    return None


def scan_claude_plugin_package(root: Path) -> tuple[PluginHit, ...]:
    """Return package-level findings for a materialized Claude plugin tree.

    Args:
        root: Scan root that may contain ``.claude-plugin/``.

    Returns:
        Undeclared executable, hidden undeclared executable or config,
        undeclared vendored or generated scope, license absence or SPDX
        mismatch, first-party checksum mismatch, size, symlink, archive
        traversal, decompression bomb, unadmitted-submodule, setuid or
        world-writable executable modes, and deceptive description
        findings. Empty when the tree is not a plugin package or every
        hook is a declared regular file. Inventory presence is not a
        finding. An empty description is not this class. Git metadata is
        not a plugin executable surface. ``.mcp.json`` stays the MCP
        class. Vendored trees are one scope finding. A matching checksum
        file, comments-only checksum file, or missing checksum file is
        not a finding. Cosign or GPG signatures are not required.
        Files or archive members nested beyond ``_MAX_PATH_DEPTH``
        components fail as excessive path depth.
    """
    plugin_dir = root / ".claude-plugin"
    if not plugin_dir.is_dir() or plugin_dir.is_symlink():
        return ()
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        manifest_path = plugin_dir / "marketplace.json"
    declared: set[str] = set()
    payload: object = {}
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        declared = _declared_paths(payload)
    hits: list[PluginHit] = []
    if _license_summary(root) == "absent":
        hits.append(
            PluginHit(
                rule_id="claude-plugin-license-missing",
                line=1,
                snippet=".claude-plugin",
                message=CLAUDE_PLUGIN_LICENSE_MISSING_MESSAGE,
                file=".claude-plugin",
            )
        )
    elif isinstance(payload, dict):
        hits.extend(_license_mismatch_hits(root, payload))
    else:
        hits.extend(_license_mismatch_hits(root, {}))
    hits.extend(_checksum_mismatch_hits(root))
    hits.extend(_unsigned_checksum_hits(root))
    hits.extend(_excessive_path_depth_hits(root))
    _, file_count, scanned_byte_count = _artifact_digest(root)
    if file_count > _MAX_PACKAGE_FILES or scanned_byte_count > _MAX_PACKAGE_BYTES:
        hits.append(
            PluginHit(
                rule_id="claude-plugin-oversized-package",
                line=1,
                snippet=".claude-plugin",
                message=CLAUDE_PLUGIN_OVERSIZED_PACKAGE_MESSAGE,
                file=".claude-plugin",
            )
        )
    hits.extend(_source_mismatch_hits(root))
    hits.extend(_archive_traversal_hits(root))
    hits.extend(_decompression_bomb_hits(root))
    hits.extend(_unadmitted_submodule_hits(root))
    hits.extend(_vendored_scope_hits(root, payload))
    hits.extend(_conflicting_identity_hits(root, payload))
    for directory_name in _HOOK_DIRS:
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            continue
        for path in _walk_entries(directory):
            relative = path.relative_to(root).as_posix()
            if _is_vendored_scope_relative(relative):
                continue
            if path.is_symlink():
                hits.append(
                    PluginHit(
                        rule_id="claude-plugin-symlink-escape",
                        line=1,
                        snippet=path.name[:120],
                        message=CLAUDE_PLUGIN_SYMLINK_ESCAPE_MESSAGE,
                        file=relative,
                    )
                )
                continue
            if not path.is_file() or path.suffix.lower() not in _EXECUTABLE_SUFFIXES:
                continue
            if relative in declared or path.name in declared:
                continue
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-undeclared-executable",
                    line=1,
                    snippet=path.name[:120],
                    message=CLAUDE_PLUGIN_UNDECLARED_EXECUTABLE_MESSAGE,
                    file=relative,
                )
            )
    hits.extend(_hidden_undeclared_executable_hits(root, declared))
    hits.extend(_insecure_file_mode_hits(root))
    hits.extend(_deceptive_description_hits(root))
    return tuple(hits)


def inspect_claude_plugin_archive(
    archive_path: Path,
    extract_root: Path,
) -> tuple[PluginHit, ...]:
    """Inspect one zip or tar plugin archive without escaping ``extract_root``.

    Members whose names leave the extract root (``../``, absolute POSIX
    paths, Windows drive or UNC prefixes) are findings and are never
    written. Members whose uncompressed size divided by compressed size
    exceeds ``_MAX_ARCHIVE_COMPRESSION_RATIO``, nested archives deeper
    than ``_MAX_ARCHIVE_NESTING_DEPTH``, or archives whose regular
    in-root members sum above ``_MAX_PACKAGE_BYTES`` are
    decompression-bomb findings and are never written. Safe members are
    materialized under ``extract_root``. Snippets record a sanitized
    member-path label only.

    Args:
        archive_path: Regular zip or tar file.
        extract_root: Bounded destination root.

    Returns:
        Path-traversal, decompression-bomb, and excessive-path-depth
        hits. Empty when every member stays inside the root, stays
        within the ratio/nesting/byte/path-depth bounds, or
        ``archive_path`` is not a readable archive. Secret literals and
        raw archive bytes never appear in snippets. Deep members are
        never extracted.
    """
    hits, safe_members = _classify_archive_members(archive_path, extract_root)
    bomb_hits = _inspect_archive_decompression_bombs(archive_path, extract_root)
    budget_hits = _archive_aggregate_budget_hits(archive_path, extract_root)
    depth_hits = _archive_member_path_depth_hits(archive_path, extract_root)
    if bomb_hits or budget_hits:
        return (*hits, *bomb_hits, *budget_hits, *depth_hits)
    for name in safe_members:
        if _path_exceeds_max_depth(name):
            continue
        _extract_archive_member(archive_path, name, extract_root)
    return (*hits, *depth_hits)


def build_claude_plugin_scan_receipt(
    root: Path,
    *,
    scanner_version: str = _SCANNER_VERSION,
    scan_started_at: str = "",
    scan_completed_at: str = "",
    catalog_payload: object | None = None,
    catalog_bytes: bytes | None = None,
) -> PluginScanReceipt:
    """Return a deterministic admission receipt for one plugin artifact.

    Args:
        root: Materialized plugin tree.
        scanner_version: Scanner release identity recorded on the receipt.
        scan_started_at: Optional caller-supplied start timestamp.
        scan_completed_at: Optional caller-supplied completion timestamp.
        catalog_payload: Optional parsed marketplace catalog document.
        catalog_bytes: Optional exact catalog file bytes.

    Returns:
        Receipt whose identity excludes wall-clock fields. ``scan_result`` is
        ``pass`` only when ``.claude-plugin/`` exists and no policy findings
        remain. Secret literals never appear on the receipt. ``policy_provenance``
        binds the running release and the exact policy digest; it is not a
        second policy hash and is not Noema admission. ``sbom_sha256`` is
        SHA-256 of a deterministic CycloneDX 1.5 document from existing
        SBOM parsers, not a second policy digest.
    """
    hits = list(_collect_plugin_hits(root))
    catalog = _catalog_identity(catalog_payload)
    hits.extend(_catalog_bind_hits(root, catalog))
    finding_summary = tuple(sorted({hit.rule_id for hit in hits}))
    identity = _plugin_identity(root)
    artifact_sha256, file_count, scanned_byte_count = _artifact_digest(root)
    marketplace_path = root / ".claude-plugin" / "marketplace.json"
    marketplace_bytes = (
        catalog_bytes if catalog_bytes is not None else _regular_file_bytes(marketplace_path)
    )
    marketplace_blob_sha = _sha256(marketplace_bytes) if marketplace_bytes else ""
    marketplace_entry_sha256 = _sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    policy_sha256 = _scanner_policy_sha256()
    provenance = _policy_provenance(policy_sha256)
    inventory = inventory_claude_plugin_capabilities(root)
    capability_inventory_sha256 = _capability_inventory_digest(inventory)
    sarif_sha256 = sarif_document_sha256(
        finding_summary_to_sarif(finding_summary, tool_version=scanner_version)
    )
    sbom_sha256 = _plugin_sbom_sha256(root)
    is_package = (root / ".claude-plugin").is_dir() and not (
        root / ".claude-plugin"
    ).is_symlink()
    scan_result = "pass" if is_package and not finding_summary else "fail"
    body = {
        "scanner_name": _SCANNER_NAME,
        "scanner_version": scanner_version,
        "scanner_policy_sha256": policy_sha256,
        "policy_provenance": provenance.as_dict(),
        "catalog_repository": catalog["catalog_repository"],
        "catalog_commit_sha": catalog["catalog_commit_sha"],
        "marketplace_blob_sha": marketplace_blob_sha,
        "marketplace_entry_sha256": marketplace_entry_sha256,
        "plugin_name": identity["plugin_name"],
        "plugin_version": identity["plugin_version"],
        "source_repository": identity["source_repository"],
        "source_commit_sha": identity["source_commit_sha"],
        "source_path": identity["source_path"],
        "artifact_sha256": artifact_sha256,
        "file_count": file_count,
        "scanned_byte_count": scanned_byte_count,
        "capability_inventory_sha256": capability_inventory_sha256,
        "sarif_sha256": sarif_sha256,
        "sbom_sha256": sbom_sha256,
        "finding_summary": list(finding_summary),
        "license_evidence_summary": _license_summary(root),
        "scan_result": scan_result,
    }
    receipt_id = _sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    )
    return PluginScanReceipt(
        scan_receipt_id=receipt_id,
        scan_started_at=scan_started_at,
        scan_completed_at=scan_completed_at,
        finding_summary=finding_summary,
        policy_provenance=provenance,
        **{
            key: value
            for key, value in body.items()
            if key not in {"finding_summary", "policy_provenance"}
        },
    )


def receipt_matches_artifact(receipt: PluginScanReceipt, root: Path) -> bool:
    """Return whether ``receipt`` still describes the current artifact bytes.

    Args:
        receipt: Previously issued receipt.
        root: Current materialized tree.

    Returns:
        True only when the current artifact digest matches the receipt.
    """
    artifact_sha256, _, _ = _artifact_digest(root)
    return artifact_sha256 == receipt.artifact_sha256 and (
        receipt.scanner_policy_sha256 == _scanner_policy_sha256()
    )


@dataclass(frozen=True, slots=True)
class PluginReceiptVerification:
    """Fail-closed comparison of a retained receipt against current bytes.

    Matching is not Noema admission. ``scan_result=pass`` on the retained
    receipt never authorizes activation.
    """

    matches: bool
    mismatches: tuple[str, ...]

    @property
    def admitted(self) -> bool:
        """Return False; receipt verification is not product admission."""
        return False

    def as_dict(self) -> dict[str, object]:
        """Return JSON-safe mismatch reasons without secret or bidi values."""
        return {
            "matches": self.matches,
            "mismatches": list(self.mismatches),
            "admitted": False,
        }


def verify_plugin_scan_receipt(
    receipt: PluginScanReceipt,
    root: Path,
    *,
    expected_policy_sha256: str | None = None,
    catalog_payload: object | None = None,
    catalog_bytes: bytes | None = None,
) -> PluginReceiptVerification:
    """Fail closed unless the receipt still binds the current artifact and policy.

    Args:
        receipt: Previously issued scan receipt.
        root: Materialized tree being admitted.
        expected_policy_sha256: Caller-pinned policy digest. When omitted,
            the current scanner policy bytes are required.
        catalog_payload: Catalog document used when the receipt was issued.
        catalog_bytes: Exact catalog bytes used when the receipt was issued.

    Returns:
        Structured mismatch field names. Empty mismatches mean the receipt
        still describes this tree and policy. ``admitted`` is always false:
        ``scan_result=pass`` is not Noema admission. Reasons never include
        secret literals or raw bidi characters. A disagreeing policy digest
        or scanner version fails closed against the running scanner.
    """
    live = build_claude_plugin_scan_receipt(
        root,
        catalog_payload=catalog_payload,
        catalog_bytes=catalog_bytes,
    )
    current_policy_sha256 = _scanner_policy_sha256()
    expected = (
        current_policy_sha256
        if expected_policy_sha256 is None
        else expected_policy_sha256
    )
    mismatches: list[str] = []
    if receipt.artifact_sha256 != live.artifact_sha256:
        mismatches.append("artifact_sha256")
    if (
        receipt.scanner_policy_sha256 != current_policy_sha256
        or receipt.scanner_policy_sha256 != expected
    ):
        mismatches.append("scanner_policy_sha256")
    if receipt.scanner_version != _SCANNER_VERSION:
        mismatches.append("scanner_version")
    if receipt.policy_provenance != live.policy_provenance:
        mismatches.append("policy_provenance")
    if receipt.sbom_sha256 != live.sbom_sha256:
        mismatches.append("sbom_sha256")
    if receipt.catalog_commit_sha != live.catalog_commit_sha:
        mismatches.append("catalog_commit_sha")
    if receipt.source_commit_sha != live.source_commit_sha:
        mismatches.append("source_commit_sha")
    if receipt.marketplace_blob_sha != live.marketplace_blob_sha:
        mismatches.append("marketplace_blob_sha")
    if receipt.scan_receipt_id != live.scan_receipt_id:
        mismatches.append("scan_receipt_id")
    if receipt.scan_result != live.scan_result:
        mismatches.append("scan_result")
    return PluginReceiptVerification(
        matches=not mismatches,
        mismatches=tuple(mismatches),
    )


def _empty_capability_inventory() -> dict[str, bool]:
    """Return every inventory key as false, in deterministic order."""
    return {key: False for key in CAPABILITY_INVENTORY_KEYS}


def _capability_inventory_digest(inventory: dict[str, bool]) -> str:
    """Return SHA-256 of the canonical JSON capability inventory."""
    return _sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    )


def _inventory_manifest_capabilities(
    content: str, inventory: dict[str, bool]
) -> None:
    """Mark MCP and process capabilities declared in one JSON manifest."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return
    servers = payload.get("mcpServers") or payload.get("mcp_servers") or {}
    if isinstance(servers, dict):
        for server in servers.values():
            if not isinstance(server, dict):
                continue
            remote_url = server.get("url")
            if isinstance(remote_url, str) and remote_url:
                inventory["mcp_remote_connect"] = True
                inventory["network_egress"] = True
            command = server.get("command")
            if isinstance(command, str) and command:
                inventory["mcp_server_start"] = True
                inventory["process_spawn"] = True
    if payload.get("hooks"):
        inventory["process_spawn"] = True


def _inventory_text_capabilities(content: str, inventory: dict[str, bool]) -> None:
    """Mark text-derived capabilities without recording secret literals."""
    if not content:
        return
    for key, pattern in _TEXT_CAPABILITY_PATTERNS:
        if pattern.search(content):
            inventory[key] = True


def _is_manifest(filename: str, posix: str) -> bool:
    """Return whether the file is a Claude plugin, marketplace, or MCP manifest."""
    if filename in {"marketplace.json", "plugin.json"} or filename in _MCP_FILENAMES:
        return True
    return posix.endswith("/.claude-plugin/marketplace.json") or posix.endswith(
        "/.claude-plugin/plugin.json"
    )


def _is_hook_surface(filename: str, posix: str) -> bool:
    """Return whether the file is a hook, script, or plugin executable surface."""
    posix_norm = f"/{posix.replace(chr(92), '/')}/"
    in_plugin_tree = (
        "/hooks/" in posix_norm
        or "/scripts/" in posix_norm
        or "/commands/" in posix_norm
        or "/.claude-plugin/" in posix_norm
    )
    if not in_plugin_tree:
        return False
    suffix = Path(filename).suffix.lower()
    return suffix in _EXECUTABLE_SUFFIXES or suffix == ""


def _is_package_lifecycle_surface(filename: str) -> bool:
    """Return whether the file is an npm ``package.json`` lifecycle surface."""
    return filename == "package.json"


def _lifecycle_script_values(content: str) -> tuple[tuple[str, str], ...]:
    """Return ``(name, script)`` pairs for npm install lifecycle scripts."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, dict):
        return ()
    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return ()
    found: list[tuple[str, str]] = []
    for name in _LIFECYCLE_SCRIPT_NAMES:
        value = scripts.get(name)
        if isinstance(value, str) and value.strip():
            found.append((name, value))
    return tuple(found)


def _script_line(content: str, body: str) -> int:
    """Return the 1-based line of a lifecycle script body in package.json."""
    if body in content:
        return _line_of(content, body)
    return _line_of(content, json.dumps(body)[1:-1])


def _package_lifecycle_hits(content: str) -> tuple[PluginHit, ...]:
    """Return unsigned-download findings from package.json lifecycle scripts.

    Only ``preinstall``, ``install``, and ``postinstall`` script strings are
    scanned. Other script names and non-script fields stay inventory.

    Args:
        content: Raw ``package.json`` text.

    Returns:
        Hits using the existing unsigned-download, pipe-to-shell, and
        unpinned-package rule identities. Empty when no lifecycle script
        downloads or executes an unsigned payload.
    """
    hits: list[PluginHit] = []
    for _name, body in _lifecycle_script_values(content):
        line = _script_line(content, body)
        match = _PIPE_TO_SHELL.search(body)
        if match is not None:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-pipe-to-shell",
                    line=line,
                    snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
                    message=CLAUDE_PLUGIN_PIPE_TO_SHELL_MESSAGE,
                )
            )
        for hit in _unsigned_executable_download_hits(body):
            hits.append(
                PluginHit(
                    rule_id=hit.rule_id,
                    line=line,
                    snippet=hit.snippet,
                    message=hit.message,
                )
            )
        for hit in _unpinned_package_install_hits(body):
            hits.append(
                PluginHit(
                    rule_id=hit.rule_id,
                    line=line,
                    snippet=hit.snippet,
                    message=hit.message,
                )
            )
    return tuple(hits)


def _already_inspected_package_json(relative: str) -> bool:
    """Return whether ``relative`` is already scanned under plugin or hook dirs."""
    posix = relative.replace("\\", "/")
    if posix.startswith(".claude-plugin/"):
        return True
    return posix.split("/", 1)[0] in _HOOK_DIRS


def _package_lifecycle_file_hits(root: Path) -> tuple[PluginHit, ...]:
    """Inspect ``package.json`` files that hook and plugin-dir walks miss.

    Args:
        root: Materialized plugin tree.

    Returns:
        Lifecycle-script findings from package.json files outside
        ``.claude-plugin/`` and hook directories. Checked-in
        ``node_modules`` copies are the vendored-scope class, not this
        lifecycle surface. Unreadable files yield no hits.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file() or path.name != "package.json":
            continue
        relative = path.relative_to(root).as_posix()
        if _already_inspected_package_json(relative):
            continue
        if "node_modules" in relative.split("/"):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            content = ""
        hits.extend(inspect_claude_plugin_file(path.name, relative, content))
    return tuple(hits)


def _github_write_token_hits(content: str) -> tuple[PluginHit, ...]:
    """Return hardcoded GitHub PAT or app-token findings without secret bodies."""
    match = _GITHUB_TOKEN.search(content)
    if match is None:
        return ()
    prefix = match.group("prefix")
    return (
        PluginHit(
            rule_id="claude-plugin-github-write-token",
            line=content[: match.start()].count("\n") + 1,
            snippet=prefix,
            message=CLAUDE_PLUGIN_GITHUB_WRITE_TOKEN_MESSAGE,
        ),
    )


def _github_merge_command_hits(content: str) -> tuple[PluginHit, ...]:
    """Return ``gh pr merge`` findings with a command label, not tokens.

    Args:
        content: Hook or manifest text.

    Returns:
        One hit when the merge CLI is present. Empty when the text only
        lists, views, or reviews pull requests.
    """
    match = _GITHUB_MERGE_COMMAND.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-github-merge-command",
            line=content[: match.start()].count("\n") + 1,
            snippet="gh pr merge",
            message=CLAUDE_PLUGIN_GITHUB_MERGE_COMMAND_MESSAGE,
        ),
    )


def _github_release_command_hits(content: str) -> tuple[PluginHit, ...]:
    """Return GitHub CLI release write-verb findings without secret bodies.

    Args:
        content: Hook or manifest text.

    Returns:
        One hit for ``create``, ``upload``, ``delete``, or ``edit``.
        ``gh release list`` and ``gh release view`` are not this class.
    """
    match = _GITHUB_RELEASE_COMMAND.search(content)
    if match is None:
        return ()
    verb = match.group("verb").lower()
    return (
        PluginHit(
            rule_id="claude-plugin-github-release-command",
            line=content[: match.start()].count("\n") + 1,
            snippet=f"gh release {verb}",
            message=CLAUDE_PLUGIN_GITHUB_RELEASE_COMMAND_MESSAGE,
        ),
    )


def _kubectl_apply_command_hits(content: str) -> tuple[PluginHit, ...]:
    """Return ``kubectl apply`` findings with a command label, not manifests.

    Args:
        content: Hook or manifest text.

    Returns:
        One hit when ``kubectl apply`` is present. ``kubectl get`` and
        README wording are not this class.
    """
    match = _KUBECTL_APPLY_COMMAND.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-kubectl-apply-command",
            line=content[: match.start()].count("\n") + 1,
            snippet="kubectl apply",
            message=CLAUDE_PLUGIN_KUBECTL_APPLY_COMMAND_MESSAGE,
        ),
    )


def _docker_push_command_hits(content: str) -> tuple[PluginHit, ...]:
    """Return ``docker push`` findings with a command label, not image names.

    Args:
        content: Hook or manifest text.

    Returns:
        One hit for ``docker push`` or ``docker image push``.
        ``docker ps``, ``docker pull``, and socket binds are not this class.
    """
    match = _DOCKER_PUSH_COMMAND.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-docker-push-command",
            line=content[: match.start()].count("\n") + 1,
            snippet="docker push",
            message=CLAUDE_PLUGIN_DOCKER_PUSH_COMMAND_MESSAGE,
        ),
    )


def _terraform_apply_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return executable terraform apply findings without vars."""
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _TERRAFORM_APPLY_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-terraform-apply-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="terraform apply",
                message=CLAUDE_PLUGIN_TERRAFORM_APPLY_COMMAND_MESSAGE,
            ),
        )
    return ()


def _helm_install_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return executable helm install findings without chart names."""
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _HELM_INSTALL_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-helm-install-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="helm install",
                message=CLAUDE_PLUGIN_HELM_INSTALL_COMMAND_MESSAGE,
            ),
        )
    return ()


def _unquoted_hash_index(line: str) -> int | None:
    """Return the index of an unquoted ``#`` shell comment, if any.

    Args:
        line: One hook or manifest line without a trailing newline.

    Returns:
        The comment index, or ``None`` when every ``#`` is quoted or escaped.
    """
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not in_single:
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return index
    return None


def _iter_unquoted_segment_bounds(line: str) -> tuple[tuple[int, int], ...]:
    """Return start/end offsets of unquoted shell command segments.

    Args:
        line: One hook or manifest line without a trailing newline.

    Returns:
        Inclusive-start exclusive-end spans split on unquoted ``&&``,
        ``||``, ``;``, ``|``, and ``&``. Quoted lookalikes stay one span.
    """
    bounds: list[tuple[int, int]] = []
    start = 0
    in_single = False
    in_double = False
    escaped = False
    length = len(line)
    index = 0
    while index < length:
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and not in_single:
            escaped = True
            index += 1
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            index += 1
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            index += 1
            continue
        if in_single or in_double:
            index += 1
            continue
        two = line[index : index + 2]
        if two in {"&&", "||"}:
            bounds.append((start, index))
            start = index + 2
            index += 2
            continue
        if char in {";", "|", "&"}:
            bounds.append((start, index))
            start = index + 1
            index += 1
            continue
        index += 1
    bounds.append((start, length))
    return tuple(bounds)


def _first_shell_token(segment: str) -> str:
    """Return the first command basename of a shell segment.

    Args:
        segment: One unquoted command fragment.

    Returns:
        A lowercase basename such as ``echo``. Empty when the fragment
        has no command token.
    """
    match = _FIRST_SHELL_TOKEN.match(segment)
    if match is None:
        return ""
    name = match.group(1).rsplit("/", 1)[-1]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name.lower()


def _is_reporting_builtin_segment(segment: str) -> bool:
    """Return whether the segment only prints text instead of running a CLI.

    Args:
        segment: One unquoted command fragment.

    Returns:
        ``True`` for ``echo``, ``printf``, and ``print``, including path
        and ``.exe`` spellings.
    """
    return _first_shell_token(segment) in _REPORTING_BUILTINS


def _manifest_command_sources(content: str) -> tuple[tuple[str, int], ...]:
    """Return structural manifest command strings with source line numbers."""
    try:
        payload = _load_manifest_json(content)
    except (_DuplicateJsonMember, _NonstandardJsonConstant, json.JSONDecodeError):
        return ()

    found: list[tuple[str, int]] = []

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key == "command" and isinstance(nested, str) and nested.strip():
                    found.append((nested, _script_line(content, nested)))
                else:
                    collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)

    collect(payload)
    return tuple(found)


def _hosted_command_sources(
    content: str, *, manifest: bool
) -> tuple[tuple[str, int], ...]:
    """Return shell text sources for one hook or structural manifest."""
    if manifest:
        return _manifest_command_sources(content)
    return ((content, 1),)


def _shell_command_context_start(line: str, offset: int) -> int | None:
    """Return the executable shell-frame start containing ``offset``.

    Args:
        line: One hook or manifest command line.
        offset: Zero-based match offset within ``line``.

    Returns:
        The start of the root, ``$(...)``, or backtick command frame.
        ``None`` means the offset is inert single- or double-quoted prose.
    """
    frames: list[tuple[str, int, str, int]] = [("", 0, "", 0)]
    escaped = False
    index = 0
    while index < offset:
        frame_end, frame_start, quote, depth = frames[-1]
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char == "'" and quote != '"':
            frames[-1] = (frame_end, frame_start, "" if quote == "'" else "'", depth)
            index += 1
            continue
        if char == '"' and quote != "'":
            frames[-1] = (frame_end, frame_start, "" if quote == '"' else '"', depth)
            index += 1
            continue
        if quote != "'" and line[index : index + 2] == "$(":
            frames.append((")", index + 2, "", 1))
            index += 2
            continue
        if quote != "'" and char == "`":
            if frame_end == "`":
                frames.pop()
            else:
                frames.append(("`", index + 1, "", 0))
            index += 1
            continue
        if quote:
            index += 1
            continue
        if frame_end == ")" and char == "(":
            frames[-1] = (frame_end, frame_start, quote, depth + 1)
        elif frame_end == ")" and char == ")":
            if depth == 1:
                frames.pop()
            else:
                frames[-1] = (frame_end, frame_start, quote, depth - 1)
        index += 1
    _frame_end, frame_start, quote, _depth = frames[-1]
    return None if quote else frame_start


def _match_starts_in_shell_assignment_value(segment: str, offset: int) -> bool:
    """Return whether ``offset`` starts inside an unquoted assignment word.

    Args:
        segment: One shell command segment.
        offset: Zero-based match offset within ``segment``.

    Returns:
        True when the current shell word before ``offset`` contains ``=``.
        An assignment followed by whitespace and a real command returns False.
    """
    prefix = segment[:offset]
    if not prefix or prefix[-1].isspace():
        return False
    return "=" in prefix.rsplit(maxsplit=1)[-1]


def _executable_command_match(    content: str, pattern: re.Pattern[str]
) -> re.Match[str] | None:
    """Return the first regex match that is an executable command context.

    Unquoted ``#`` comments, quoted prose, shell assignment values, and
    ``echo``/``printf``/``print`` segments are not executable. Direct
    commands inside ``$(...)`` or backticks remain executable.

    Args:
        content: Hook or manifest text.
        pattern: Compiled command regex.

    Returns:
        The first executable match, or ``None``.
    """
    if not content:
        return None
    for match in pattern.finditer(content):
        line_start = content.rfind("\n", 0, match.start()) + 1
        line_end = content.find("\n", match.start())
        if line_end < 0:
            line_end = len(content)
        line = content[line_start:line_end]
        relative = match.start() - line_start
        context_start = _shell_command_context_start(line, relative)
        if context_start is None:
            continue
        context = line[context_start:]
        context_relative = relative - context_start
        comment_at = _unquoted_hash_index(context)
        if comment_at is not None and context_relative >= comment_at:
            continue
        for segment_start, segment_end in _iter_unquoted_segment_bounds(context):
            if segment_start <= context_relative < segment_end:
                segment = context[segment_start:segment_end]
                segment_relative = context_relative - segment_start
                if not _is_reporting_builtin_segment(
                    segment
                ) and not _match_starts_in_shell_assignment_value(
                    segment, segment_relative
                ):
                    return match
                break
    return None
def _vercel_deploy_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``vercel deploy`` findings with a command label, not tokens.

    Args:
        content: Hook or manifest text.

    Returns:
        One hit when an executable ``vercel deploy`` is present.
        ``vercel ls``, README wording, hook comments, and echo/printf
        lookalikes are not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _VERCEL_DEPLOY_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-vercel-deploy-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="vercel deploy",
                message=CLAUDE_PLUGIN_VERCEL_DEPLOY_COMMAND_MESSAGE,
            ),
        )
    return ()


def _fly_deploy_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``fly deploy`` findings with a command label, not app names.

    Args:
        content: Hook or manifest text.

    Returns:
        One hit for executable ``fly deploy`` or ``flyctl deploy``.
        ``fly status``, hook comments, and echo/printf lookalikes are
        not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _FLY_DEPLOY_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-fly-deploy-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="fly deploy",
                message=CLAUDE_PLUGIN_FLY_DEPLOY_COMMAND_MESSAGE,
            ),
        )
    return ()


def _aws_deploy_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return AWS deploy-write findings with a command label, not secrets."""
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _AWS_DEPLOY_COMMAND)
        if match is None:
            continue
        snippet = " ".join(match.group(0).lower().split())
        return (
            PluginHit(
                rule_id="claude-plugin-aws-deploy-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet=snippet,
                message=CLAUDE_PLUGIN_AWS_DEPLOY_COMMAND_MESSAGE,
            ),
        )
    return ()


def _gcloud_deploy_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return gcloud deploy findings with a service-qualified command label."""
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _GCLOUD_DEPLOY_COMMAND)
        if match is None:
            continue
        service = match.group("service").lower()
        return (
            PluginHit(
                rule_id="claude-plugin-gcloud-deploy-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="gcloud " + service + " deploy",
                message=CLAUDE_PLUGIN_GCLOUD_DEPLOY_COMMAND_MESSAGE,
            ),
        )
    return ()


def _az_deploy_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return Azure webapp deploy findings with a command label, not names."""
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _AZ_DEPLOY_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-az-deploy-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="az webapp deploy",
                message=CLAUDE_PLUGIN_AZ_DEPLOY_COMMAND_MESSAGE,
            ),
        )
    return ()


def _is_literal_s3_download(
    content: str, match: re.Match[str]
) -> bool:
    """Return whether one direct S3 command provably reads to a local path."""
    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.start())
    if line_end < 0:
        line_end = len(content)
    line = content[line_start:line_end]
    relative = match.start() - line_start
    command_end = match.end() - line_start
    for start, end in _iter_unquoted_segment_bounds(line):
        if start <= relative < end:
            operands = line[command_end:end].split()
            return (
                len(operands) == 2
                and operands[0].lower().startswith("s3://")
                and not operands[1].lower().startswith("s3://")
                and not operands[1].startswith("-")
                and all(
                    re.fullmatch(r"[A-Za-z0-9._~:/+-]+", operand)
                    for operand in operands
                )
            )
    return False


def _aws_s3_write_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return S3-destination write findings without copying operand URIs."""
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        search_from = 0
        while search_from < len(source):
            fragment = source[search_from:]
            match = _executable_command_match(fragment, _AWS_S3_WRITE_COMMAND)
            if match is None:
                break
            absolute_start = search_from + match.start()
            if not _is_literal_s3_download(fragment, match):
                verb = match.group("verb").lower()
                return (
                    PluginHit(
                        rule_id="claude-plugin-aws-s3-write-command",
                        line=first_line + source[:absolute_start].count("\n"),
                        snippet="aws s3 " + verb,
                        message=CLAUDE_PLUGIN_AWS_S3_WRITE_COMMAND_MESSAGE,
                    ),
                )
            search_from += match.end()
    return ()


def _az_containerapp_up_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``az containerapp up`` findings with a command label, not names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit when executable ``az containerapp up`` is present.
        ``az account show``, comments, and echo lookalikes are not this
        class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _AZ_CONTAINERAPP_UP_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-az-containerapp-up-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="az containerapp up",
                message=CLAUDE_PLUGIN_AZ_CONTAINERAPP_UP_COMMAND_MESSAGE,
            ),
        )
    return ()


def _npm_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``npm publish`` findings with a command label, not tokens.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``npm publish``. ``npm pack``, comments,
        and echo lookalikes are not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _NPM_PUBLISH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-npm-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="npm publish",
                message=CLAUDE_PLUGIN_NPM_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _pypi_upload_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``twine upload`` findings with a command label, not filenames.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``twine upload``. ``pip install`` is not
        this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _PYPI_UPLOAD_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-pypi-upload-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="twine upload",
                message=CLAUDE_PLUGIN_PYPI_UPLOAD_COMMAND_MESSAGE,
            ),
        )
    return ()


def _cargo_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``cargo publish`` findings with a command label, not crate names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``cargo publish``. ``cargo check`` is not
        this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _CARGO_PUBLISH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-cargo-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="cargo publish",
                message=CLAUDE_PLUGIN_CARGO_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _pnpm_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``pnpm publish`` findings with a command label, not tokens.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``pnpm publish``. ``npm publish`` and
        ``yarn npm publish`` stay the npm class. ``pnpm list`` is not
        this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _PNPM_PUBLISH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-pnpm-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="pnpm publish",
                message=CLAUDE_PLUGIN_PNPM_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _uv_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``uv publish`` findings with a command label, not tokens.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``uv publish``. ``twine upload`` stays
        the PyPI class. ``uv pip list`` is not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _UV_PUBLISH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-uv-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="uv publish",
                message=CLAUDE_PLUGIN_UV_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _poetry_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``poetry publish`` findings with a command label, not names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``poetry publish``. ``twine upload`` stays
        the PyPI class. Comments and echo lookalikes are not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _POETRY_PUBLISH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-poetry-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="poetry publish",
                message=CLAUDE_PLUGIN_POETRY_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _gem_push_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``gem push`` findings with a command label, not gem names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``gem push``. ``gem list``, comments, and
        echo lookalikes are not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _GEM_PUSH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-gem-push-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="gem push",
                message=CLAUDE_PLUGIN_GEM_PUSH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _nuget_push_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``nuget push`` findings with a command label, not package names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``nuget push`` or ``dotnet nuget push``.
        ``nuget list`` is not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _NUGET_PUSH_COMMAND)
        if match is None:
            continue
        return (
            PluginHit(
                rule_id="claude-plugin-nuget-push-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet="nuget push",
                message=CLAUDE_PLUGIN_NUGET_PUSH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _pub_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``pub publish`` findings with a command label, not package names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``dart pub publish``, ``flutter pub
        publish``, or legacy ``pub publish``. ``dart pub get`` is not
        this class. ``pnpm publish`` stays the pnpm class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _PUB_PUBLISH_COMMAND)
        if match is None:
            continue
        sdk = match.group("sdk")
        if sdk:
            snippet = sdk.lower() + " pub publish"
        else:
            snippet = "pub publish"
        return (
            PluginHit(
                rule_id="claude-plugin-pub-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet=snippet,
                message=CLAUDE_PLUGIN_PUB_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _hex_publish_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``hex publish`` findings with a command label, not package names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``hex publish`` or ``mix hex.publish``.
        ``hex info`` is not this class. ``dart pub publish`` stays the
        pub.dev class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _HEX_PUBLISH_COMMAND)
        if match is None:
            continue
        token = match.group(0).lower()
        snippet = "mix hex.publish" if token.startswith("mix ") else "hex publish"
        return (
            PluginHit(
                rule_id="claude-plugin-hex-publish-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet=snippet,
                message=CLAUDE_PLUGIN_HEX_PUBLISH_COMMAND_MESSAGE,
            ),
        )
    return ()


def _conda_upload_command_hits(
    content: str, *, manifest: bool = False
) -> tuple[PluginHit, ...]:
    """Return ``conda upload`` findings with a command label, not package names.

    Args:
        content: Hook or manifest text.
        manifest: When true, only structural command values are scanned.

    Returns:
        One hit for executable ``conda upload`` or ``anaconda upload``.
        ``conda list`` is not this class.
    """
    for source, first_line in _hosted_command_sources(content, manifest=manifest):
        match = _executable_command_match(source, _CONDA_UPLOAD_COMMAND)
        if match is None:
            continue
        snippet = match.group("cli").lower() + " upload"
        return (
            PluginHit(
                rule_id="claude-plugin-conda-upload-command",
                line=first_line + source[: match.start()].count("\n"),
                snippet=snippet,
                message=CLAUDE_PLUGIN_CONDA_UPLOAD_COMMAND_MESSAGE,
            ),
        )
    return ()


def _dynamic_eval_hits(content: str) -> tuple[PluginHit, ...]:
    """Return findings for eval/exec/compile/Function on hook surfaces."""
    match = _DYNAMIC_EVAL.search(content)
    if match is None:
        return ()
    token = match.group(0).strip()
    if "(" in token:
        label = token.split("(", 1)[0].strip()[:40]
    else:
        label = token.split()[0][:40]
    return (
        PluginHit(
            rule_id="claude-plugin-dynamic-eval",
            line=content[: match.start()].count("\n") + 1,
            snippet=label,
            message=CLAUDE_PLUGIN_DYNAMIC_EVAL_MESSAGE,
        ),
    )


def _docker_socket_hits(content: str) -> tuple[PluginHit, ...]:
    """Return host Docker-socket findings from hook or manifest text."""
    match = _DOCKER_SOCKET.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-docker-socket",
            line=content[: match.start()].count("\n") + 1,
            snippet=match.group(0)[:120],
            message=CLAUDE_PLUGIN_DOCKER_SOCKET_MESSAGE,
        ),
    )


def _browser_profile_hits(content: str) -> tuple[PluginHit, ...]:
    """Return host browser-profile store findings from hook or manifest text.

    Path-like Chrome, Chromium, and Firefox profile stores fail closed.
    A bare product name such as ``Firefox`` is inventory, not this finding.

    Args:
        content: Hook or manifest text.

    Returns:
        Zero or one hit. Snippets omit secret literals and raw bidi.
    """
    match = _BROWSER_PROFILE.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-browser-profile-access",
            line=content[: match.start()].count("\n") + 1,
            snippet=_sanitize_plugin_snippet(match.group(0))[:120],
            message=CLAUDE_PLUGIN_BROWSER_PROFILE_MESSAGE,
        ),
    )


def _credential_store_label(match: re.Match[str], default_label: str) -> str:
    """Return a path label for one host cookie or token store.

    Args:
        match: One credential-store regular-expression match.
        default_label: Canonical path for non-SSH stores.

    Returns:
        A short path label with no secret values.
    """
    if default_label:
        return default_label
    return f"~/.ssh/{match.group('name').lower()}"


def _credential_store_hits(content: str) -> tuple[PluginHit, ...]:
    """Return host cookie and token store findings from hook or manifest text.

    ``~/.netrc``, cloud credentials, GitHub CLI hosts, Docker registry
    auth, cookie jars, and SSH private keys fail closed. Chrome and
    Firefox profile stores stay ``claude-plugin-browser-profile-access``.
    Snippets are path labels, not secret values or raw bidi.

    Args:
        content: Hook or manifest text.

    Returns:
        Zero or more hits, one per distinct store path label.
    """
    hits: list[PluginHit] = []
    seen: set[str] = set()
    for pattern, label in _CREDENTIAL_STORE_PATTERNS:
        for match in pattern.finditer(content):
            snippet = _sanitize_plugin_snippet(
                _credential_store_label(match, label)
            )
            if snippet in seen:
                continue
            seen.add(snippet)
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-credential-store-access",
                    line=content[: match.start()].count("\n") + 1,
                    snippet=snippet[:120],
                    message=CLAUDE_PLUGIN_CREDENTIAL_STORE_MESSAGE,
                )
            )
    return tuple(hits)


def _secret_to_network_hits(content: str) -> tuple[PluginHit, ...]:
    """Return findings when a named secret is copied into a network client."""
    match = _SECRET_TO_NETWORK.search(content)
    if match is None:
        return ()
    name = match.group("name")
    client = "curl"
    lowered = match.group(0).lower()
    if lowered.startswith("wget"):
        client = "wget"
    elif lowered.startswith("fetch"):
        client = "fetch"
    return (
        PluginHit(
            rule_id="claude-plugin-secret-to-network",
            line=content[: match.start()].count("\n") + 1,
            snippet=f"{client} ${name}"[:120],
            message=CLAUDE_PLUGIN_SECRET_TO_NETWORK_MESSAGE,
        ),
    )


def _secret_to_prompt_sink_label(line: str) -> str:
    """Return a short sink label for a secret-to-prompt line."""
    lowered = line.lower()
    if re.search(r"\b(?:echo|printf)\b", lowered):
        return "echo"
    if re.search(r"\bprint\s*\(", lowered):
        return "print"
    if re.search(r"\b(?:logging|logger)\.\w+", lowered):
        return "logger"
    if "subprocess" in lowered:
        return "subprocess"
    return "prompt"


def _secret_to_prompt_hits(content: str) -> tuple[PluginHit, ...]:
    """Return findings when a named secret is copied into a prompt, log, or child env.

    Curl, wget, and fetch copies stay ``claude-plugin-secret-to-network``.
    Reading a secret into a local variable is not this class. Hardcoded
    ``sk-`` literals stay ``claude-plugin-provider-secret``. Child
    ``env=os.environ`` inheritance is not a copy beyond inheritance.

    Args:
        content: Hook, command, or manifest text.

    Returns:
        Zero or one hit. Snippets are sink plus env name, without secret
        values or raw bidi.
    """
    for match in _SECRET_REF.finditer(content):
        line = content[content.rfind("\n", 0, match.start()) + 1 :].split("\n", 1)[0]
        if _SECRET_TO_NETWORK.search(line) is not None:
            continue
        if _PROMPT_LOG_SINK.search(line) is None:
            continue
        name_match = _NAMED_SECRET_TOKEN.search(match.group(0))
        name = name_match.group(0) if name_match is not None else "SECRET"
        return (
            PluginHit(
                rule_id="claude-plugin-secret-to-prompt",
                line=content[: match.start()].count("\n") + 1,
                snippet=_sanitize_plugin_snippet(
                    f"{_secret_to_prompt_sink_label(line)} ${name}"
                ),
                message=CLAUDE_PLUGIN_SECRET_TO_PROMPT_MESSAGE,
            ),
        )
    ident = _SECRET_LOG_IDENT.search(content)
    if ident is not None:
        return (
            PluginHit(
                rule_id="claude-plugin-secret-to-prompt",
                line=content[: ident.start()].count("\n") + 1,
                snippet="logger api_key",
                message=CLAUDE_PLUGIN_SECRET_TO_PROMPT_MESSAGE,
            ),
        )
    env_match = _SUBPROCESS_SECRET_ENV.search(content)
    if env_match is None:
        return ()
    env_name = _NAMED_SECRET_TOKEN.search(env_match.group(0))
    snippet = (
        f"subprocess ${env_name.group(0)}" if env_name is not None else "subprocess env"
    )
    return (
        PluginHit(
            rule_id="claude-plugin-secret-to-prompt",
            line=content[: env_match.start()].count("\n") + 1,
            snippet=_sanitize_plugin_snippet(snippet),
            message=CLAUDE_PLUGIN_SECRET_TO_PROMPT_MESSAGE,
        ),
    )


def _sanitize_plugin_snippet(value: str) -> str:
    """Return a bidi-free snippet without token bodies or sk- secret literals."""
    cleaned = _CONCEALED_CHAR.sub("", value)
    cleaned = _GITHUB_TOKEN.sub(lambda match: match.group("prefix"), cleaned)
    cleaned = _SK_LITERAL.sub("sk-", cleaned)
    return cleaned.strip()[:120]


def _downloaded_path_executed(content: str, path: str) -> bool:
    """Return whether ``path`` is invoked as a command after download."""
    pattern = re.compile(
        rf"(?:^|&&|;|\n)\s*(?:(?:ba)?sh\s+)?{re.escape(path)}\b",
        re.MULTILINE,
    )
    return pattern.search(content) is not None


def _unsigned_executable_download_hits(content: str) -> tuple[PluginHit, ...]:
    """Return unsigned runtime-download findings from hook or script text."""
    hits: list[PluginHit] = []
    seen_lines: set[int] = set()

    def add(match: re.Match[str]) -> None:
        """Record one download finding, skipping a second hit on the same line."""
        line = content[: match.start()].count("\n") + 1
        if line in seen_lines:
            return
        seen_lines.add(line)
        hits.append(
            PluginHit(
                rule_id="claude-plugin-unsigned-executable-download",
                line=line,
                snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
                message=CLAUDE_PLUGIN_UNSIGNED_EXECUTABLE_DOWNLOAD_MESSAGE,
            )
        )

    for match in _PIPE_TO_INTERPRETER.finditer(content):
        add(match)
    chmod_paths = {
        match.group("path").strip("'\"") for match in _CHMOD_PLUS_X.finditer(content)
    }
    for match in _DOWNLOAD_TO_FILE.finditer(content):
        path = match.group("path").strip("'\"")
        if path in chmod_paths or _downloaded_path_executed(content, path):
            add(match)
    return tuple(hits)


def _unpinned_package_install_hits(content: str) -> tuple[PluginHit, ...]:
    """Return unpinned URL package-install findings from hook or script text."""
    match = _UNPINNED_PACKAGE_INSTALL.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-unpinned-package-install",
            line=content[: match.start()].count("\n") + 1,
            snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
            message=CLAUDE_PLUGIN_UNPINNED_PACKAGE_INSTALL_MESSAGE,
        ),
    )


def _inspect_manifest(content: str) -> tuple[PluginHit, ...]:
    """Return floating-ref, duplicate-JSON, MCP, concealment, and secret hits."""
    hits: list[PluginHit] = list(_concealment_hits(content))
    try:
        payload = _load_manifest_json(content)
    except _DuplicateJsonMember as exc:
        return (
            PluginHit(
                rule_id="claude-plugin-duplicate-json-member",
                line=_line_of(content, str(exc)),
                snippet=str(exc)[:120],
                message=CLAUDE_PLUGIN_DUPLICATE_JSON_MESSAGE,
            ),
        )
    except _NonstandardJsonConstant as exc:
        token = str(exc)
        return (
            PluginHit(
                rule_id="claude-plugin-nonstandard-json-constant",
                line=_line_of(content, token),
                snippet=_sanitize_plugin_snippet(token)[:120],
                message=CLAUDE_PLUGIN_NONSTANDARD_JSON_MESSAGE,
            ),
        )
    except json.JSONDecodeError:
        return ()
    for entry in _plugin_entries(payload):
        ref = _source_ref(entry)
        if isinstance(ref, str) and not _FULL_SHA.fullmatch(ref):
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-floating-git-ref",
                    line=_line_of(content, ref),
                    snippet=ref[:120],
                    message=CLAUDE_PLUGIN_FLOATING_REF_MESSAGE,
                )
            )
    hits.extend(_mcp_hits(payload, content))
    hits.extend(_secret_to_mcp_hits(payload, content))
    hits.extend(_normalized_name_hits(payload, content))
    hits.extend(_conflicting_entry_name_hits(payload, content))
    secret = _PROVIDER_SECRET.search(content)
    if secret is not None:
        hits.append(
            PluginHit(
                rule_id="claude-plugin-provider-secret",
                line=content[: secret.start()].count("\n") + 1,
                snippet=secret.group(0),
                message=CLAUDE_PLUGIN_PROVIDER_SECRET_MESSAGE,
            )
        )
    return tuple(hits)


def _concealment_hits(content: str) -> tuple[PluginHit, ...]:
    """Return hits for concealed control or bidirectional characters."""
    match = _CONCEALED_CHAR.search(content)
    if match is None:
        return ()
    codepoint = f"U+{ord(match.group(0)):04X}"
    return (
        PluginHit(
            rule_id="claude-plugin-concealed-identity",
            line=_line_of(content, match.group(0)),
            snippet=codepoint,
            message=CLAUDE_PLUGIN_CONCEALED_IDENTITY_MESSAGE,
        ),
    )


class _DuplicateJsonMember(ValueError):
    """Raised when a JSON object repeats a member name."""


class _NonstandardJsonConstant(ValueError):
    """Raised when JSON contains NaN, Infinity, or -Infinity."""


def _load_manifest_json(content: str) -> object:
    """Parse JSON while rejecting duplicate members and non-standard constants."""

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Fail closed when a JSON object repeats a member name."""
        seen: set[str] = set()
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in seen:
                raise _DuplicateJsonMember(key)
            seen.add(key)
            result[key] = value
        return result

    def parse_constant(name: str) -> object:
        """Fail closed on NaN, Infinity, and -Infinity."""
        raise _NonstandardJsonConstant(name)

    return json.loads(
        content,
        object_pairs_hook=object_pairs,
        parse_constant=parse_constant,
    )


def _mcp_is_bounded(server: dict) -> bool:
    """Return whether one MCP server declaration has schema plus identity."""
    schema = server.get("schema") or server.get("inputSchema")
    if not isinstance(schema, dict) or not schema:
        return False
    if isinstance(server.get("url"), str) and server["url"]:
        auth = server.get("auth") or server.get("authentication")
        return isinstance(auth, dict) and bool(auth)
    if isinstance(server.get("command"), str) and server["command"]:
        identity = server.get("source") or server.get("identity") or server.get("sha")
        return bool(identity)
    return False


def _mcp_hits(payload: object, content: str) -> tuple[PluginHit, ...]:
    """Return unbounded MCP server declarations from one manifest."""
    if not isinstance(payload, dict):
        return ()
    servers = payload.get("mcpServers") or payload.get("mcp_servers")
    if not isinstance(servers, dict) or not servers:
        return ()
    hits: list[PluginHit] = []
    for name, server in servers.items():
        if isinstance(server, dict) and _mcp_is_bounded(server):
            continue
        token = name if isinstance(name, str) else "mcp"
        hits.append(
            PluginHit(
                rule_id="claude-plugin-unbounded-mcp",
                line=_line_of(content, token),
                snippet=token[:120],
                message=CLAUDE_PLUGIN_UNBOUNDED_MCP_MESSAGE,
            )
        )
    return tuple(hits)


def _secret_to_mcp_hits(payload: object, content: str) -> tuple[PluginHit, ...]:
    """Return hits when MCP env, args, or command carry a named secret.

    Curl/wget/fetch copies stay the network class. Prompt and log copies
    stay the prompt class. Snippets are the env name only.

    Args:
        payload: Parsed MCP or plugin JSON.
        content: Original manifest text for line numbers.

    Returns:
        Zero or one secret-to-MCP hit.
    """
    if not isinstance(payload, dict):
        return ()
    servers = payload.get("mcpServers") or payload.get("mcp_servers")
    if not isinstance(servers, dict) or not servers:
        return ()
    for _name, server in servers.items():
        if not isinstance(server, dict):
            continue
        env = server.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                blob = f"{key} {value}" if isinstance(value, str) else str(key)
                match = _NAMED_SECRET_TOKEN.search(blob)
                if match is not None:
                    token = match.group(0)
                    return (
                        PluginHit(
                            rule_id="claude-plugin-secret-to-mcp",
                            line=_line_of(content, token),
                            snippet=token,
                            message=CLAUDE_PLUGIN_SECRET_TO_MCP_MESSAGE,
                        ),
                    )
        args = server.get("args")
        if isinstance(args, list):
            for arg in args:
                if not isinstance(arg, str):
                    continue
                match = _NAMED_SECRET_TOKEN.search(arg)
                if match is not None:
                    token = match.group(0)
                    return (
                        PluginHit(
                            rule_id="claude-plugin-secret-to-mcp",
                            line=_line_of(content, token),
                            snippet=token,
                            message=CLAUDE_PLUGIN_SECRET_TO_MCP_MESSAGE,
                        ),
                    )
        command = server.get("command")
        if isinstance(command, str):
            match = _NAMED_SECRET_TOKEN.search(command)
            if match is not None:
                token = match.group(0)
                return (
                    PluginHit(
                        rule_id="claude-plugin-secret-to-mcp",
                        line=_line_of(content, token),
                        snippet=token,
                        message=CLAUDE_PLUGIN_SECRET_TO_MCP_MESSAGE,
                    ),
                )
    return ()


def _normalized_name_hits(payload: object, content: str) -> tuple[PluginHit, ...]:
    """Return hits when a plugin identity name is not Unicode NFC.

    Combining-mark (NFD) names conceal catalog identity. ASCII and
    precomposed Hangul/Latin names are already NFC and stay negative.

    Args:
        payload: Parsed plugin or marketplace JSON.
        content: Original manifest text for line numbers.

    Returns:
        Zero or more hits. Snippets are the label ``name`` only.
    """
    hits: list[PluginHit] = []
    for entry in _plugin_entries(payload):
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        if unicodedata.normalize("NFC", name) == name:
            continue
        hits.append(
            PluginHit(
                rule_id="claude-plugin-inconsistent-normalized-name",
                line=_line_of(content, name),
                snippet="name",
                message=CLAUDE_PLUGIN_NORMALIZED_NAME_MESSAGE,
            )
        )
    return tuple(hits)


def _nfc_identity_name(value: object) -> str | None:
    """Return an NFC identity name, or ``None`` when absent or not NFC."""
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        return None
    return normalized


def _conflict_identity_hit() -> PluginHit:
    """Return the single conflicting-identity finding with a label snippet."""
    return PluginHit(
        rule_id="claude-plugin-conflicting-identity",
        line=1,
        snippet="name",
        message=CLAUDE_PLUGIN_CONFLICTING_IDENTITY_MESSAGE,
    )


def _conflicting_entry_name_hits(
    payload: object, content: str
) -> tuple[PluginHit, ...]:
    """Return a hit when one marketplace document repeats an NFC name."""
    seen: set[str] = set()
    for entry in _plugin_entries(payload):
        name = _nfc_identity_name(entry.get("name"))
        if name is None:
            continue
        if name in seen:
            return (
                PluginHit(
                    rule_id="claude-plugin-conflicting-identity",
                    line=_line_of(content, name),
                    snippet="name",
                    message=CLAUDE_PLUGIN_CONFLICTING_IDENTITY_MESSAGE,
                ),
            )
        seen.add(name)
    return ()


def _conflicting_identity_hits(
    root: Path, payload: object
) -> tuple[PluginHit, ...]:
    """Return one hit when plugin, skill, or command NFC names collide.

    Non-NFC names stay the normalized-name class. Vendored trees are skipped.
    Duplicate names emit one finding, not one per file.

    Args:
        root: Materialized plugin tree.
        payload: Parsed plugin or marketplace JSON.

    Returns:
        Zero or one conflicting-identity hit.
    """
    seen: set[str] = set()
    for entry in _plugin_entries(payload):
        name = _nfc_identity_name(entry.get("name"))
        if name is None:
            continue
        if name in seen:
            return (_conflict_identity_hit(),)
        seen.add(name)
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if _is_vendored_scope_relative(relative):
            continue
        name = _identity_name_from_path(path, relative)
        if name is None:
            continue
        if name in seen:
            return (_conflict_identity_hit(),)
        seen.add(name)
    return ()


def _identity_name_from_path(path: Path, relative: str) -> str | None:
    """Return an NFC identity name declared on a skill or command file."""
    posix = f"/{relative.replace(chr(92), '/')}/"
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if path.name == "skill.json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        return _nfc_identity_name(payload.get("name"))
    markdown = path.name.lower().endswith(".md") and any(
        marker in posix for marker in ("/skills/", "/commands/", "/agents/")
    )
    if _is_skill_surface(path) or markdown:
        text, _line = _markdown_name(content)
        return _nfc_identity_name(text)
    return None


def _markdown_name(content: str) -> tuple[str, int]:
    """Return the YAML frontmatter name and its 1-based line."""
    match = _FRONTMATTER.match(content)
    if match is None:
        return "", 0
    body = match.group("body")
    start_line = content[: match.start("body")].count("\n") + 1
    for offset, line in enumerate(body.splitlines()):
        if not line.lower().startswith("name:"):
            continue
        value = line.split(":", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if value in {"|", ">", "|-", "|+", ">-", ">+"}:
            return "", start_line + offset
        return value, start_line + offset
    return "", 0


def _plugin_entries(payload: object) -> Iterable[dict]:
    """Yield plugin objects from a marketplace document or single plugin."""
    if isinstance(payload, dict):
        plugins = payload.get("plugins")
        if isinstance(plugins, list):
            for item in plugins:
                if isinstance(item, dict):
                    yield item
            return
        yield payload


def _source_ref(entry: dict) -> str | None:
    """Return the Git ref declared on a plugin source object."""
    source = entry.get("source")
    if isinstance(source, dict):
        ref = source.get("ref") or source.get("sha")
        return ref if isinstance(ref, str) else None
    ref = entry.get("ref")
    return ref if isinstance(ref, str) else None


def _declared_paths(payload: object) -> set[str]:
    """Return hook and command paths declared by a plugin manifest."""
    declared: set[str] = set()
    entries = list(_plugin_entries(payload))
    for entry in entries:
        hooks = entry.get("hooks") or {}
        if isinstance(hooks, dict):
            for value in hooks.values():
                _collect_declared(value, declared)
        commands = entry.get("commands") or []
        if isinstance(commands, list):
            for value in commands:
                _collect_declared(value, declared)
    return declared


def _collect_declared(value: object, declared: set[str]) -> None:
    """Add string command paths from one manifest value."""
    if isinstance(value, str):
        declared.add(value)
        declared.add(Path(value).name)
        return
    if isinstance(value, dict):
        command = value.get("command") or value.get("path") or value.get("script")
        if isinstance(command, str):
            declared.add(command)
            declared.add(Path(command).name)
        return
    if isinstance(value, list):
        for item in value:
            _collect_declared(item, declared)


def _is_vendored_scope_relative(relative: str) -> bool:
    """Return whether ``relative`` is vendored, generated, or lockfile-adjacent.

    ``vendor/``, ``node_modules/``, ``dist/``, and ``*.min.js`` copies are
    third-party or generated scope. First-party hooks such as
    ``hooks/pre.sh`` are not this class.
    """
    posix = relative.replace("\\", "/")
    parts = [part for part in posix.split("/") if part]
    if any(part in _VENDORED_SCOPE_DIR_NAMES for part in parts):
        return True
    return bool(parts) and parts[-1].endswith(".min.js")


def _declared_vendored_scope_paths(payload: object) -> set[str]:
    """Return bounded ``files[]`` paths declared on plugin identities.

    Args:
        payload: Parsed plugin or marketplace JSON.

    Returns:
        Normalized path labels. Non-list ``files`` values and non-string
        entries are ignored so admission cannot treat inventory as
        permission.
    """
    declared: set[str] = set()
    for entry in _plugin_entries(payload):
        files = entry.get("files") or []
        if not isinstance(files, list):
            continue
        for item in files:
            if not isinstance(item, str):
                continue
            normalized = item.replace("\\", "/").strip().strip("/")
            if normalized:
                declared.add(normalized)
    return declared


def _vendored_scope_is_declared(
    relative: str, declared: set[str], admitted: tuple[str, ...]
) -> bool:
    """Return whether ``relative`` is bound by files[] or an admitted nested plugin."""
    posix = relative.replace("\\", "/").strip("/")
    return any(
        posix == item or posix.startswith(item + "/")
        for item in (*declared, *admitted)
    )


def _admitted_nested_scope_prefixes(root: Path) -> tuple[str, ...]:
    """Return SHA-bound nested plugin paths that are already admitted.

    Nested packages under ``vendor/`` with a recursively admitted immutable
    SHA stay the submodule class. They are identity-bound dependencies, not
    undeclared leftpad copies.
    """
    prefixes: list[str] = []
    for pointer in _iter_submodules(root):
        if not _submodule_is_admitted(root, pointer):
            continue
        path = pointer.path.replace("\\", "/").strip("/")
        if path:
            prefixes.append(path)
    return tuple(prefixes)


def _vendored_scope_label(relative: str) -> str:
    """Return a bidi-free vendored-root or min.js path label."""
    posix = relative.replace("\\", "/")
    parts = [part for part in posix.split("/") if part]
    for index, part in enumerate(parts):
        if part in _VENDORED_SCOPE_DIR_NAMES:
            return _sanitize_path_snippet("/".join(parts[: index + 1]) + "/")
    return _sanitize_path_snippet(posix)


def _vendored_scope_hits(root: Path, payload: object) -> tuple[PluginHit, ...]:
    """Return one finding when undeclared vendored or generated code is present.

    Args:
        root: Materialized plugin tree.
        payload: Parsed plugin or marketplace JSON.

    Returns:
        At most one hit. Snippets are path labels such as ``vendor/`` or
        ``app.min.js``. File contents, secrets, and raw bidi never appear.
        Empty when every vendored path is declared in ``files[]`` or the
        tree has no vendor, node_modules, dist, or min.js copy. Git
        metadata and admitted nested plugins are not this class.
    """
    declared = _declared_vendored_scope_paths(payload)
    admitted = _admitted_nested_scope_prefixes(root)
    for path in _walk_entries(root):
        relative = path.relative_to(root).as_posix()
        if _is_git_metadata_path(relative):
            continue
        if not _is_vendored_scope_relative(relative):
            continue
        if _vendored_scope_is_declared(relative, declared, admitted):
            continue
        label = _vendored_scope_label(relative)
        return (
            PluginHit(
                rule_id="claude-plugin-vendored-scope-undeclared",
                line=1,
                snippet=label,
                message=CLAUDE_PLUGIN_VENDORED_SCOPE_MESSAGE,
                file=label,
            ),
        )
    return ()


def _is_git_metadata_path(relative: str) -> bool:
    """Return whether ``relative`` is Git metadata, not a plugin surface.

    ``.git/`` internals, gitlink files named ``.git``, and
    ignore/attributes/modules files are VCS metadata. They are not Claude
    plugin executable or config surfaces, including when nested under a
    vendor path.
    """
    return any(
        part == ".git" or part in _GIT_METADATA_NAMES for part in relative.split("/")
    )


def _is_hidden_plugin_path(relative: str) -> bool:
    """Return whether a package-relative path uses a hidden name or directory."""
    return any(part.startswith(".") for part in relative.split("/"))


def _is_hidden_executable_or_config_surface(path: Path, relative: str) -> bool:
    """Return whether a hidden path is an executable, script, or config surface.

    Documented ``.mcp.json`` and ``.claude-plugin`` manifests are not this
    class. Git metadata is not a plugin executable surface.
    """
    if not _is_hidden_plugin_path(relative) or _is_git_metadata_path(relative):
        return False
    if path.name in _MCP_FILENAMES:
        return False
    parts = relative.split("/")
    if (
        len(parts) >= 2
        and parts[-2] == ".claude-plugin"
        and parts[-1] in _CLAUDE_PLUGIN_MANIFEST_NAMES
    ):
        return False
    suffix = path.suffix.lower()
    return (
        suffix in _EXECUTABLE_SUFFIXES
        or suffix == ""
        or suffix in _HIDDEN_CONFIG_SUFFIXES
    )


def _hidden_undeclared_executable_hits(
    root: Path, declared: set[str]
) -> tuple[PluginHit, ...]:
    """Return findings for hidden undeclared executable or config surfaces.

    Args:
        root: Materialized plugin tree.
        declared: Hook and command paths declared in the plugin manifest.

    Returns:
        Hits for hidden paths such as ``.bin/run.sh`` or ``.hooks/secret.py``
        that are executable, script, or config surfaces and are not
        declared. Empty when every hidden surface is Git metadata,
        documented MCP or plugin manifest, or already declared. Non-hidden
        extras under ``hooks/``, ``scripts/``, or ``commands/`` stay
        ``claude-plugin-undeclared-executable``. Vendored trees stay
        ``claude-plugin-vendored-scope-undeclared``.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in declared:
            continue
        if _is_vendored_scope_relative(relative):
            continue
        if not _is_hidden_executable_or_config_surface(path, relative):
            continue
        hits.append(
            PluginHit(
                rule_id="claude-plugin-hidden-undeclared-executable",
                line=1,
                snippet=_sanitize_path_snippet(path.name),
                message=CLAUDE_PLUGIN_HIDDEN_UNDECLARED_EXECUTABLE_MESSAGE,
                file=relative,
            )
        )
    return tuple(hits)


def _is_mode_sensitive_surface(path: Path, relative: str) -> bool:
    """Return whether ``relative`` is an executable or hook host-fs surface.

    LICENSE, README, and other documentation without an executable suffix
    are not this class. MCP manifests stay the MCP class.
    """
    if path.name in _MCP_FILENAMES or _is_git_metadata_path(relative):
        return False
    posix = relative.replace("\\", "/")
    first = posix.split("/", 1)[0]
    suffix = path.suffix.lower()
    if first in _HOOK_DIRS:
        return True
    return suffix in _EXECUTABLE_SUFFIXES


def _insecure_file_mode_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return findings for setuid, setgid, or world-writable hook files.

    Args:
        root: Materialized plugin tree.

    Returns:
        Hits for executable or hook files whose mode has setuid, setgid,
        or other-write. Empty when every such file is ``0755``/``0644``,
        vendored, a symlink, or Git metadata. LICENSE world-write is not
        this class. Snippets are path labels.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if _is_vendored_scope_relative(relative):
            continue
        if not _is_mode_sensitive_surface(path, relative):
            continue
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            continue
        snippet = _sanitize_path_snippet(path.name)
        if mode & (stat.S_ISUID | stat.S_ISGID):
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-setuid-executable",
                    line=1,
                    snippet=snippet,
                    message=CLAUDE_PLUGIN_SETUID_EXECUTABLE_MESSAGE,
                    file=relative,
                )
            )
        if mode & stat.S_IWOTH:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-world-writable-executable",
                    line=1,
                    snippet=snippet,
                    message=CLAUDE_PLUGIN_WORLD_WRITABLE_EXECUTABLE_MESSAGE,
                    file=relative,
                )
            )
    return tuple(hits)


def _deceptive_description_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return findings when a description denies inventoried capabilities.

    Plugin, skill, and command description fields are compared with the
    package capability inventory. Inventory is evidence, not permission:
    a true capability is not this finding unless the description denies
    it. Empty or missing descriptions are not this class.

    Args:
        root: Materialized plugin tree.

    Returns:
        Zero or more hits bound to the description source file. Snippets
        omit secret literals and raw bidi.
    """
    inventory = inventory_claude_plugin_capabilities(root)
    hits: list[PluginHit] = []
    for relative, line, text in _iter_plugin_descriptions(root):
        denied = _denied_capabilities(text)
        if not any(inventory.get(key) for key in denied):
            continue
        hits.append(
            PluginHit(
                rule_id="claude-plugin-deceptive-description",
                line=line,
                snippet=_sanitize_plugin_snippet(text),
                message=CLAUDE_PLUGIN_DECEPTIVE_DESCRIPTION_MESSAGE,
                file=relative,
            )
        )
    return tuple(hits)


def _iter_plugin_descriptions(root: Path) -> tuple[tuple[str, int, str], ...]:
    """Yield ``(relative path, line, description)`` from plugin surfaces."""
    found: list[tuple[str, int, str]] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _is_json_description_surface(path.name, relative):
            found.extend(_json_descriptions(content, relative))
        elif _is_markdown_description_surface(path.name, relative):
            text, line = _markdown_description(content)
            if text.strip():
                found.append((relative, line, text))
    return tuple(found)


def _is_json_description_surface(name: str, relative: str) -> bool:
    """Return whether ``relative`` is a JSON plugin, marketplace, or skill file."""
    posix = relative.replace("\\", "/")
    if name in _DESCRIPTION_JSON_NAMES and posix.startswith(".claude-plugin/"):
        return True
    return name == "skill.json"


def _is_markdown_description_surface(name: str, relative: str) -> bool:
    """Return whether ``relative`` is a skill or command markdown surface."""
    if not name.lower().endswith(".md"):
        return False
    posix = f"/{relative.replace(chr(92), '/')}/"
    return any(marker in posix for marker in _DESCRIPTION_MARKDOWN_DIRS)


def _json_descriptions(content: str, relative: str) -> tuple[tuple[str, int, str], ...]:
    """Return description strings from one JSON plugin or skill document."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return ()
    found: list[tuple[str, int, str]] = []
    for text in _iter_description_strings(payload):
        if not text.strip():
            continue
        found.append((relative, _line_of(content, text), text))
    return tuple(found)


def _iter_description_strings(payload: object) -> Iterable[str]:
    """Yield ``description`` string fields from plugin JSON objects."""
    if isinstance(payload, dict):
        value = payload.get("description")
        if isinstance(value, str):
            yield value
        for nested in payload.values():
            yield from _iter_description_strings(nested)
    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_description_strings(item)


def _markdown_description(content: str) -> tuple[str, int]:
    """Return the YAML frontmatter description and its 1-based line.

    Inline ``description:`` values are collected. Block scalars and missing
    frontmatter yield an empty description rather than inventing a
    missing-description finding.

    Args:
        content: Markdown file text.

    Returns:
        Description text and line number. ``("", 0)`` when none exists.
    """
    match = _FRONTMATTER.match(content)
    if match is None:
        return "", 0
    body = match.group("body")
    start_line = content[: match.start("body")].count("\n") + 1
    for offset, line in enumerate(body.splitlines()):
        if not line.lower().startswith("description:"):
            continue
        value = line.split(":", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if value in {"|", ">", "|-", "|+", ">-", ">+"}:
            return "", start_line + offset
        return value, start_line + offset
    return "", 0


def _denied_capabilities(description: str) -> frozenset[str]:
    """Return capabilities a description claims not to use.

    Args:
        description: Plugin, skill, or command description text.

    Returns:
        Subset of write, network, GitHub write, credential, remote MCP,
        and shell keys the text denies. Empty when the text makes no
        such claim.
    """
    text = description.strip()
    denied: set[str] = set()
    if _READ_ONLY_CLAIM.search(text):
        denied.update(("filesystem_write", "github_write"))
    if _LOCAL_ONLY_CLAIM.search(text):
        denied.update(("network_egress", "mcp_remote_connect"))
    if _INNOCUOUS_CLAIM.search(text):
        denied.update(
            (
                "filesystem_write",
                "network_egress",
                "github_write",
                "credential_access",
                "mcp_remote_connect",
            )
        )
    if _NO_CREDENTIAL_CLAIM.search(text):
        denied.add("credential_access")
    if _NO_SHELL_CLAIM.search(text):
        denied.add("shell_execution")
    return frozenset(denied)


def _line_of(content: str, token: str) -> int:
    """Return the 1-based line where ``token`` first appears."""
    index = content.find(token)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _scanner_policy_sha256() -> str:
    """Return SHA-256 of the exact detector policy bytes used for this scan."""
    return _sha256(Path(__file__).read_bytes())


def _policy_provenance(policy_sha256: str) -> PolicyProvenance:
    """Return provenance bound to the running scanner release and policy digest."""
    return PolicyProvenance(
        schema_version=_POLICY_PROVENANCE_SCHEMA_VERSION,
        source_repository=_SCANNER_SOURCE_REPOSITORY,
        scanner_release_version=_SCANNER_VERSION,
        scanner_policy_sha256=policy_sha256,
    )


def _plugin_sbom_components(root: Path) -> list[dict[str, object]]:
    """Return sorted CycloneDX components from existing SBOM parsers.

    Malformed or unreadable manifests yield an empty component list rather
    than crashing the receipt. Lockfile preference stays in
    ``collect_components``.
    """
    from appguardrail_core.sbom import collect_components

    try:
        components = collect_components(root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return []
    return sorted(
        components,
        key=lambda item: (
            str(item.get("name") or ""),
            str(item.get("version") or ""),
            str(item.get("purl") or ""),
        ),
    )


def _plugin_sbom_document(root: Path) -> dict[str, object]:
    """Return a deterministic CycloneDX 1.5 document for ``root``.

    Args:
        root: Materialized plugin tree.

    Returns:
        The existing ``build_sbom`` document with sorted components. The
        metadata name is the plugin identity or ``claude-plugin``. Secret
        literals are not copied into the document by this helper.
    """
    from appguardrail_core.sbom import build_sbom

    name = _plugin_identity(root)["plugin_name"].strip() or "claude-plugin"
    return build_sbom(_plugin_sbom_components(root), name)


def _plugin_sbom_sha256(root: Path) -> str:
    """Return SHA-256 of the canonical CycloneDX document for ``root``."""
    return _sha256(
        json.dumps(
            _plugin_sbom_document(root),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def _path_component_count(relative: str) -> int:
    """Return the number of non-empty path components in ``relative``.

    Args:
        relative: A POSIX or mixed-separator path.

    Returns:
        Component count after dropping empty parts and ``.``. ``/`` and
        ``./`` are zero.
    """
    cleaned = relative.replace("\\", "/").strip("/")
    if not cleaned:
        return 0
    return len([part for part in cleaned.split("/") if part and part != "."])


def _path_exceeds_max_depth(relative: str) -> bool:
    """Return whether ``relative`` nests past ``_MAX_PATH_DEPTH``.

    Args:
        relative: A POSIX or mixed-separator path.

    Returns:
        ``True`` when the component count is greater than the bound.
    """
    return _path_component_count(relative) > _MAX_PATH_DEPTH


def _excessive_path_depth_hit(relative: str, display_file: str | None = None) -> PluginHit:
    """Return one excessive-path-depth finding with a sanitized label.

    Args:
        relative: Offending relative path.
        display_file: Optional archive path recorded on the hit.

    Returns:
        One finding. Snippets never include secrets or bidi.
    """
    return PluginHit(
        rule_id="claude-plugin-excessive-path-depth",
        line=1,
        snippet="nested-path",
        message=CLAUDE_PLUGIN_EXCESSIVE_PATH_DEPTH_MESSAGE,
        file=display_file,
    )


def _archive_member_path_depth_hits(
    archive_path: Path, extract_root: Path
) -> tuple[PluginHit, ...]:
    """Return one depth finding for the first too-deep in-root member.

    Args:
        archive_path: Candidate zip or tar file.
        extract_root: Bounded destination used to skip zip-slip names.

    Returns:
        At most one hit. Traversal names stay the traversal class.
        Members are not extracted.
    """
    names, opened = _archive_member_names(archive_path)
    if not opened:
        return ()
    display = _archive_display_path(archive_path, extract_root)
    for name in names:
        if _archive_member_escapes(name, extract_root):
            continue
        if _path_exceeds_max_depth(name):
            return (_excessive_path_depth_hit(name, display),)
    return ()


def _excessive_path_depth_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return bounded depth findings for a materialized plugin tree.

    Args:
        root: Plugin scan root.

    Returns:
        One tree finding for the first too-deep regular file or symlink,
        plus at most one finding per archive. Zip-slip members stay
        traversal. Nested zip/tar members stay decompression-bomb.
    """
    hits: list[PluginHit] = []
    tree_hit = False
    for path in _walk_entries(root):
        try:
            relative = path.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if not tree_hit and _path_exceeds_max_depth(relative):
            hits.append(_excessive_path_depth_hit(relative, relative))
            tree_hit = True
            continue
        try:
            is_archive = path.is_file() and not path.is_symlink() and _is_archive_path(path)
        except OSError:
            continue
        if is_archive:
            hits.extend(_archive_member_path_depth_hits(path, root))
    return tuple(hits)


def _walk_entries(root: Path) -> tuple[Path, ...]:
    """Yield regular files and symlinks without following linked directories."""
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda path: path.name, reverse=True)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    found.append(entry)
                    continue
                if entry.is_dir():
                    stack.append(entry)
                    continue
                if entry.is_file():
                    found.append(entry)
            except OSError:
                continue
    return tuple(sorted(found, key=lambda path: path.as_posix()))


def _regular_file_bytes(path: Path) -> bytes:
    """Return bytes of a regular file, or empty bytes for missing/symlink paths."""
    try:
        if not path.is_file() or path.is_symlink():
            return b""
        return path.read_bytes()
    except OSError:
        return b""


def _artifact_digest(root: Path) -> tuple[str, int, int]:
    """Return SHA-256, file count, and byte count for regular files under ``root``."""
    hasher = hashlib.sha256()
    file_count = 0
    scanned_byte_count = 0
    for path in _walk_entries(root):
        if path.is_symlink():
            hasher.update(b"symlink:")
            hasher.update(path.relative_to(root).as_posix().encode())
            hasher.update(b"\0")
            continue
        payload = _regular_file_bytes(path)
        relative = path.relative_to(root).as_posix().encode()
        hasher.update(relative)
        hasher.update(b"\0")
        hasher.update(str(len(payload)).encode())
        hasher.update(b"\0")
        hasher.update(payload)
        hasher.update(b"\0")
        file_count += 1
        scanned_byte_count += len(payload)
    return hasher.hexdigest(), file_count, scanned_byte_count


def _license_summary(root: Path) -> str:
    """Return present license path names or ``absent`` without legal approval."""
    names = [
        path.relative_to(root).as_posix()
        for path in _license_evidence_paths(root)
    ]
    return ",".join(names) if names else "absent"


def _license_evidence_paths(root: Path) -> tuple[Path, ...]:
    """Return LICENSE* and NOTICE* regular files, never following symlinks."""
    found: list[Path] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        upper = path.name.upper()
        if upper.startswith("LICENSE") or upper.startswith("NOTICE"):
            found.append(path)
    return tuple(found)


def _spdx_tokens_from_text(text: str) -> set[str]:
    """Return known SPDX identifiers found in ``text`` without legal approval."""
    return {match.group(1).upper() for match in _SPDX_TOKEN.finditer(text)}


def _declared_license_expression(payload: dict) -> str:
    """Return a string license field from a plugin manifest, if present."""
    value = payload.get("license")
    return value if isinstance(value, str) else ""


def _license_mismatch_hits(root: Path, payload: dict) -> tuple[PluginHit, ...]:
    """Return a finding when SPDX tokens in license evidence disagree."""
    tokens: set[str] = set()
    declared = _declared_license_expression(payload)
    tokens.update(_spdx_tokens_from_text(declared))
    for path in _license_evidence_paths(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        tokens.update(_spdx_tokens_from_text(text))
    if len(tokens) < 2:
        return ()
    snippet = ",".join(sorted(tokens))[:120]
    return (
        PluginHit(
            rule_id="claude-plugin-license-mismatch",
            line=1,
            snippet=snippet,
            message=CLAUDE_PLUGIN_LICENSE_MISMATCH_MESSAGE,
            file=".claude-plugin",
        ),
    )


def _is_first_party_checksum_file(path: Path) -> bool:
    """Return whether ``path`` is a first-party checksum file.

    Named ``SHA256SUMS``, ``SHA256SUMS.txt``, and ``checksums.sha256``
    files count anywhere in the tree. A ``*.sha256`` file counts only
    when it sits next to a regular ``plugin.json``.
    """
    if path.name in _CHECKSUM_FILENAMES:
        return True
    if not path.name.lower().endswith(".sha256"):
        return False
    sibling = path.parent / "plugin.json"
    try:
        if not sibling.is_file() or sibling.is_symlink():
            return False
    except OSError:
        return False
    return True


def _checksum_file_paths(root: Path) -> tuple[Path, ...]:
    """Return regular first-party checksum files, never following symlinks."""
    found: list[Path] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        if _is_first_party_checksum_file(path):
            found.append(path)
    return tuple(found)


def _checksum_listed_name_escapes(name: str) -> bool:
    """Return whether a checksum path would escape the plugin tree."""
    if not name or "\x00" in name or _CONCEALED_CHAR.search(name):
        return True
    raw = name.replace("\\", "/")
    if (
        raw.startswith("/")
        or name.startswith("\\\\")
        or raw.startswith("//")
        or _WINDOWS_DRIVE.match(name)
        or _WINDOWS_DRIVE.match(raw)
    ):
        return True
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    return any(part == ".." or part.startswith("..") for part in parts)


def _parse_gnu_checksum_line(line: str) -> tuple[str, str] | None:
    """Return ``(digest, filename)`` from one GNU ``sha256sum`` row."""
    if len(line) < 66:
        return None
    digest = line[:64]
    if _SHA256_HEX.match(digest) is None:
        return None
    separator = line[64:66]
    if separator in {"  ", " *"}:
        name = line[66:].strip().strip("'\"")
    elif line[64] == "\t":
        name = line[65:].strip().strip("'\"")
    else:
        return None
    if not name:
        return None
    return digest.lower(), name


def _parse_checksum_entries(text: str, checksum_path: Path) -> tuple[tuple[str, str], ...]:
    """Return digest and listed-name pairs from one checksum file.

    GNU ``sha256sum`` rows bind enumerated files. A ``*.sha256`` file whose
    entire body is one hex digest binds the sibling without the suffix.
    Comment and blank lines are ignored. Named ``checksums.sha256`` files
    are not treated as a lone digest of a ``checksums`` sibling.
    """
    stripped = text.strip()
    if (
        checksum_path.name not in _CHECKSUM_FILENAMES
        and checksum_path.name.lower().endswith(".sha256")
        and _SHA256_HEX.match(stripped) is not None
    ):
        sibling = checksum_path.name[: -len(".sha256")]
        if sibling:
            return ((stripped.lower(), sibling),)
        return ()
    entries: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parsed = _parse_gnu_checksum_line(line)
        if parsed is None:
            continue
        entries.append(parsed)
    return tuple(entries)


def _resolve_checksum_target(
    root: Path, checksum_path: Path, listed: str
) -> Path | None:
    """Return the in-root regular file named by ``listed``, if any.

    Resolution tries the checksum directory, the plugin root, then
    ``.claude-plugin/<basename>`` so a root ``SHA256SUMS`` can name the
    plugin artifact as ``plugin.json``. Symlinks and escaped paths yield
    ``None``.
    """
    if _checksum_listed_name_escapes(listed):
        return None
    raw = listed.replace("\\", "/")
    try:
        root_resolved = root.resolve()
    except OSError:
        return None
    candidates = (
        checksum_path.parent / raw,
        root / raw,
        root / ".claude-plugin" / Path(raw).name,
    )
    for candidate in candidates:
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root_resolved):
                continue
            return resolved
        except OSError:
            continue
    return None


def _checksum_mismatch_hit(listed: str, checksum_file: str) -> PluginHit:
    """Return one checksum-mismatch finding with a path-label snippet."""
    return PluginHit(
        rule_id="claude-plugin-checksum-mismatch",
        line=1,
        snippet=_sanitize_path_snippet(listed),
        message=CLAUDE_PLUGIN_CHECKSUM_MISMATCH_MESSAGE,
        file=checksum_file,
    )


def _checksum_mismatch_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return findings when a first-party checksum disagrees with disk bytes.

    Missing checksum files are not this class. Cosign, GPG, or network
    signature checks are not performed. Snippets are listed path labels,
    never digests or secret literals.
    """
    hits: list[PluginHit] = []
    for path in _checksum_file_paths(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            hits.append(_checksum_mismatch_hit(path.name, relative))
            continue
        entries = _parse_checksum_entries(text, path)
        for digest, listed in entries:
            target = _resolve_checksum_target(root, path, listed)
            if target is None:
                hits.append(_checksum_mismatch_hit(listed, relative))
                continue
            actual = _sha256(_regular_file_bytes(target))
            if actual != digest:
                hits.append(_checksum_mismatch_hit(listed, relative))
    return tuple(hits)


_CHECKSUM_SIGNATURE_SUFFIXES: Final = (".sig", ".asc", ".gpg", ".bundle")


def _checksum_has_signature_file(checksum_path: Path) -> bool:
    """Return whether a non-empty sibling signature file exists.

    Args:
        checksum_path: First-party checksum file.

    Returns:
        True when a regular, non-symlink sibling ``.sig``, ``.asc``,
        ``.gpg``, ``.bundle``, or ``cosign.bundle`` has a non-zero size.
        Empty files, missing files, and unreadable paths are False.
        Bytes are not cryptographically verified.
    """
    names = [checksum_path.name + suffix for suffix in _CHECKSUM_SIGNATURE_SUFFIXES]
    names.append("cosign.bundle")
    for name in names:
        candidate = checksum_path.parent / name
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if candidate.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def _unsigned_checksum_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return findings when checksum digest rows have no sibling signature.

    Missing checksum files and comment-only checksum files are not this
    class. Network Cosign or GPG verification is not performed. Snippets
    are checksum filenames, never digests or secret literals.
    """
    hits: list[PluginHit] = []
    for path in _checksum_file_paths(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not _parse_checksum_entries(text, path):
            continue
        if _checksum_has_signature_file(path):
            continue
        hits.append(
            PluginHit(
                rule_id="claude-plugin-unsigned-checksum",
                line=1,
                snippet=_sanitize_path_snippet(path.name),
                message=CLAUDE_PLUGIN_UNSIGNED_CHECKSUM_MESSAGE,
                file=relative,
            )
        )
    return tuple(hits)


def _empty_identity() -> dict[str, str]:
    """Return blank plugin identity fields."""
    return {
        "plugin_name": "",
        "plugin_version": "",
        "source_repository": "",
        "source_commit_sha": "",
        "source_path": "",
    }


def _empty_catalog_identity() -> dict[str, str]:
    """Return blank catalog and plugin identity fields."""
    return {
        "catalog_repository": "",
        "catalog_commit_sha": "",
        **_empty_identity(),
    }


def _catalog_identity(payload: object | None) -> dict[str, str]:
    """Return catalog repository/SHA plus first plugin identity from a catalog."""
    identity = _empty_catalog_identity()
    if not isinstance(payload, dict):
        return identity
    repo = payload.get("repository") or payload.get("catalog_repository")
    sha = (
        payload.get("commit")
        or payload.get("catalog_commit_sha")
        or payload.get("sha")
    )
    identity.update(_identity_from_payload(payload))
    if isinstance(repo, str):
        identity["catalog_repository"] = repo
    if isinstance(sha, str):
        identity["catalog_commit_sha"] = sha
    return identity


def _catalog_bind_hits(root: Path, catalog: dict[str, str]) -> tuple[PluginHit, ...]:
    """Return findings when an external catalog disagrees with the artifact."""
    hits: list[PluginHit] = []
    catalog_sha = catalog.get("catalog_commit_sha") or ""
    if catalog_sha and not _FULL_SHA.fullmatch(catalog_sha):
        hits.append(
            PluginHit(
                rule_id="claude-plugin-floating-git-ref",
                line=1,
                snippet=catalog_sha[:120],
                message=CLAUDE_PLUGIN_FLOATING_REF_MESSAGE,
                file="marketplace.json",
            )
        )
    plugin = _plugin_identity(root)
    for field in ("plugin_name", "source_repository", "source_commit_sha"):
        left, right = catalog.get(field) or "", plugin.get(field) or ""
        if left and right and left != right:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet=field,
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file="marketplace.json",
                )
            )
            break
    return tuple(hits)


def _identity_from_payload(payload: object) -> dict[str, str]:
    """Return bounded identity from one parsed marketplace or plugin document."""
    identity = _empty_identity()
    entries = list(_plugin_entries(payload))
    if not entries:
        return identity
    entry = entries[0]
    name = entry.get("name")
    if not isinstance(name, str) and isinstance(payload, dict):
        name = payload.get("name")
    identity["plugin_name"] = name if isinstance(name, str) else ""
    version = entry.get("version")
    if not isinstance(version, str) and isinstance(payload, dict):
        version = payload.get("version")
    identity["plugin_version"] = version if isinstance(version, str) else ""
    source = entry.get("source")
    if isinstance(source, dict):
        repo = source.get("repo") or source.get("source")
        identity["source_repository"] = repo if isinstance(repo, str) else ""
        identity["source_commit_sha"] = _source_ref(entry) or ""
        path_value = source.get("path")
        identity["source_path"] = path_value if isinstance(path_value, str) else ""
        return identity
    if isinstance(entry.get("ref"), str):
        identity["source_commit_sha"] = entry["ref"]
    return identity


def _identity_from_file(path: Path) -> dict[str, str]:
    """Return identity from one regular JSON file, or blanks on parse failure."""
    payload_bytes = _regular_file_bytes(path)
    if not payload_bytes:
        return _empty_identity()
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _empty_identity()
    return _identity_from_payload(payload)


def _source_mismatch_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return hits when catalog identity disagrees with the retrieved artifact."""
    plugin = _identity_from_file(root / ".claude-plugin" / "plugin.json")
    market = _identity_from_file(root / ".claude-plugin" / "marketplace.json")
    hits: list[PluginHit] = []
    for field in ("source_commit_sha", "source_repository"):
        left, right = plugin[field], market[field]
        if left and right and left != right:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet=field,
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file=".claude-plugin/plugin.json",
                )
            )
            break
    path_value = plugin["source_path"] or market["source_path"]
    if path_value:
        parts = Path(path_value).parts
        if path_value.startswith("/") or ".." in parts:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet="source.path",
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file=".claude-plugin/plugin.json",
                )
            )
        elif not (root / path_value).exists():
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet="source.path",
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file=".claude-plugin/plugin.json",
                )
            )
    return tuple(hits)


def _plugin_identity(root: Path) -> dict[str, str]:
    """Return bounded plugin identity fields from the local manifest."""
    for name in ("plugin.json", "marketplace.json"):
        identity = _identity_from_file(root / ".claude-plugin" / name)
        if any(identity.values()):
            return identity
    return _empty_identity()


def _collect_plugin_hits(root: Path) -> tuple[PluginHit, ...]:
    """Combine package-level, hook, and package.json lifecycle findings."""
    hits = list(scan_claude_plugin_package(root))
    for mcp_name in _MCP_FILENAMES:
        mcp_path = root / mcp_name
        if mcp_path.is_symlink() or not mcp_path.is_file():
            continue
        hits.extend(
            inspect_claude_plugin_bytes(
                mcp_path.name,
                mcp_name,
                _regular_file_bytes(mcp_path),
            )
        )
    plugin_dir = root / ".claude-plugin"
    if not plugin_dir.is_dir() or plugin_dir.is_symlink():
        return tuple(hits)
    for path in _walk_entries(plugin_dir):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        hits.extend(
            inspect_claude_plugin_bytes(
                path.name,
                relative,
                _regular_file_bytes(path),
            )
        )
    for directory_name in _HOOK_DIRS:
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            continue
        for path in _walk_entries(directory):
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if _is_vendored_scope_relative(relative):
                continue
            hits.extend(
                inspect_claude_plugin_bytes(
                    path.name,
                    relative,
                    _regular_file_bytes(path),
                )
            )
    hits.extend(_package_lifecycle_file_hits(root))
    hits.extend(_skill_supply_chain_hits(root))
    hits.extend(_instruction_override_hits(root))
    return tuple(hits)


def _is_skill_surface(path: Path) -> bool:
    """Return whether ``path`` is a released #1036 skill, agent, or command surface.

    Basename ``SKILL.md``, ``skill.json``, ``agent.md``, and ``*.skill.md``
    remain surfaces. Markdown under a ``commands/`` or ``agents/`` directory
    is the same instruction class. Root ``AGENTS.md``, ``README.md``, and
    command shell files are not this class.

    Args:
        path: Candidate plugin file.

    Returns:
        True when the file is a skill, agent, or command instruction surface.
    """
    name = path.name
    if name in _SKILL_SURFACE_NAMES or name.endswith(".skill.md"):
        return True
    if not name.lower().endswith(".md"):
        return False
    return any(part.lower() in _SKILL_MARKDOWN_DIRS for part in path.parts[:-1])


def _instruction_override_content_hits(
    content: str, relative: str
) -> tuple[PluginHit, ...]:
    """Return hide-actions, self-modify, and goal-escalation hits from one file.

    The three rule identities are one instruction-to-the-model family. This
    detector does not copy #1036 injection or exfil regular expressions.

    Args:
        content: Skill, command, or agent instruction text.
        relative: Repository-relative display path.

    Returns:
        Zero or more hits. Snippets omit secret literals and raw bidi.
    """
    hits: list[PluginHit] = []
    for rule_id, pattern, message in _INSTRUCTION_OVERRIDE_RULES:
        match = pattern.search(content)
        if match is None:
            continue
        hits.append(
            PluginHit(
                rule_id=rule_id,
                line=content[: match.start()].count("\n") + 1,
                snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
                message=message,
                file=relative,
            )
        )
    return tuple(hits)


def _instruction_override_hits(root: Path) -> tuple[PluginHit, ...]:
    """Fail closed on skill, command, or agent text that overrides the task.

    Hide-actions, self-modify, and goal-escalation wording share this walker.
    README, root ``AGENTS.md``, vendored copies, and command shell files are
    not this class. #1036 injection and exfil identities stay on their rules.

    Args:
        root: Materialized plugin tree.

    Returns:
        Hits whose ``rule_id`` values are the instruction-override family.
        Empty when no skill, command, or agent surface carries that wording.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file() or not _is_skill_surface(path):
            continue
        relative = path.relative_to(root).as_posix()
        if _is_vendored_scope_relative(relative):
            continue
        payload = _regular_file_bytes(path)
        content = payload.decode("utf-8", errors="replace")
        hits.extend(_instruction_override_content_hits(content, relative))
    return tuple(hits)


def _skill_supply_chain_hits(root: Path) -> tuple[PluginHit, ...]:
    """Reuse released #1036 rule identities on plugin skill, agent, and command files.

    Homoglyph, injection, exfiltration, and placeholder detection stay in
    ``scanner/rules/skill_supply_chain.yml``. This adapter does not copy those
    regular expressions. Missing rule files yield no hits.

    Args:
        root: Materialized plugin tree.

    Returns:
        Hits whose ``rule_id`` values are the released skill-supply-chain
        identities. Empty when no skill, agent, or command surface exists
        or the YAML pack is absent.
    """
    from scanner.cli.appguardrail import _scan_file

    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file() or not _is_skill_surface(path):
            continue
        relative = path.relative_to(root).as_posix()
        if _is_vendored_scope_relative(relative):
            continue
        for finding in _scan_file(path, root):
            rule_id = str(finding.get("rule_id") or "")
            if rule_id not in _SKILL_SUPPLY_CHAIN_RULE_IDS:
                continue
            hits.append(
                PluginHit(
                    rule_id=rule_id,
                    line=int(finding.get("line") or 1),
                    snippet=str(finding.get("snippet") or path.name)[:120],
                    message=str(finding.get("message") or ""),
                    file=str(finding.get("file") or relative),
                )
            )
    return tuple(hits)


@dataclass(frozen=True, slots=True)
class _SubmodulePointer:
    """One nested submodule, gitlink, or .gitmodules path record."""

    path: str
    file: str
    recorded_sha: str


def _sanitize_path_snippet(value: str) -> str:
    """Return a bidi-free path label without file contents or secrets."""
    cleaned = _CONCEALED_CHAR.sub("", value.replace("\\", "/"))
    return cleaned[:120] or "path"


def _is_archive_path(path: Path) -> bool:
    """Return whether ``path`` uses a zip or tar suffix."""
    name = path.name.lower()
    return name.endswith(_ARCHIVE_SUFFIXES)


def _archive_display_path(archive_path: Path, extract_root: Path) -> str:
    """Return a root-relative archive path, or the basename when unbound."""
    try:
        return archive_path.relative_to(extract_root).as_posix()
    except ValueError:
        return archive_path.name


def _archive_member_escapes(member_name: str, extract_root: Path) -> bool:
    """Return whether an archive member would resolve outside ``extract_root``."""
    if not member_name or "\x00" in member_name or _CONCEALED_CHAR.search(member_name):
        return True
    stripped = _CONCEALED_CHAR.sub("", member_name)
    raw = stripped.replace("\\", "/")
    if (
        raw.startswith("/")
        or stripped.startswith("\\\\")
        or raw.startswith("//")
        or _WINDOWS_DRIVE.match(stripped)
        or _WINDOWS_DRIVE.match(raw)
    ):
        return True
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    if any(part == ".." or part.startswith("..") for part in parts):
        return True
    try:
        root = extract_root.resolve()
    except OSError:
        return True
    dest = Path(os.path.normpath(os.path.join(str(root), raw)))
    try:
        dest.relative_to(root)
    except ValueError:
        return True
    return False


def _traversal_hit(archive_file: str, member_name: str) -> PluginHit:
    """Return one archive path-traversal finding with a sanitized snippet."""
    return PluginHit(
        rule_id="claude-plugin-archive-path-traversal",
        line=1,
        snippet=_sanitize_path_snippet(member_name),
        message=CLAUDE_PLUGIN_ARCHIVE_PATH_TRAVERSAL_MESSAGE,
        file=archive_file,
    )


def _archive_member_names(archive_path: Path) -> tuple[tuple[str, ...], bool]:
    """Return member names and whether ``archive_path`` opened as an archive."""
    try:
        if archive_path.is_symlink() or not archive_path.is_file():
            return (), False
    except OSError:
        return (), False
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                return tuple(archive.namelist()), True
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as archive:
                return tuple(member.name for member in archive.getmembers()), True
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return (), False
    return (), False


def _archive_aggregate_budget_hits(
    archive_path: Path, extract_root: Path
) -> tuple[PluginHit, ...]:
    """Return a bomb finding when in-root regular members exceed the byte budget.

    Uses archive metadata only (zip ``ZipInfo.file_size``, tar regular
    ``TarInfo.size``). Traversal members and directories are omitted.
    Payload bytes are not read or written.

    Args:
        archive_path: Candidate zip or tar file.
        extract_root: Bounded destination root used to exclude escapes.

    Returns:
        One decompression-bomb hit when the summed uncompressed size of
        regular in-root members is greater than ``_MAX_PACKAGE_BYTES``.
        Empty when the archive is unreadable, not an archive, or the
        total stays within budget.
    """
    total = _archive_regular_in_root_bytes(archive_path, extract_root)
    if total is None or total <= _MAX_PACKAGE_BYTES:
        return ()
    relative = _archive_display_path(archive_path, extract_root)
    return (_decompression_bomb_hit(relative, archive_path.name),)


def _archive_regular_in_root_bytes(
    archive_path: Path, extract_root: Path
) -> int | None:
    """Return summed uncompressed bytes of regular in-root members.

    Args:
        archive_path: Candidate zip or tar file.
        extract_root: Bounded destination root used to exclude escapes.

    Returns:
        Non-negative byte total, or ``None`` when the archive cannot be
        read as zip/tar metadata. Directories and escaping names are
        skipped. Payload contents are not read.
    """
    kind = _archive_kind_from_name(archive_path.name)
    try:
        if kind == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                total = 0
                for info in archive.infolist():
                    if _zip_member_is_dir(info):
                        continue
                    if _archive_member_escapes(info.filename, extract_root):
                        continue
                    total += info.file_size
                return total
        if kind == "tar":
            with tarfile.open(archive_path) as archive:
                total = 0
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    if _archive_member_escapes(member.name, extract_root):
                        continue
                    total += member.size
                return total
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return None
    return 0


def _classify_archive_members(
    archive_path: Path, extract_root: Path
) -> tuple[tuple[PluginHit, ...], tuple[str, ...]]:
    """Split archive members into traversal hits and in-root extract names."""
    names, readable = _archive_member_names(archive_path)
    relative = _archive_display_path(archive_path, extract_root)
    if not readable:
        if _is_archive_path(archive_path):
            return ((_traversal_hit(relative, archive_path.name),), ())
        return (), ()
    hits: list[PluginHit] = []
    safe: list[str] = []
    for name in names:
        if _archive_member_escapes(name, extract_root):
            hits.append(_traversal_hit(relative, name))
            continue
        if name.endswith("/") or name.endswith("\\"):
            continue
        safe.append(name)
    return tuple(hits), tuple(safe)


def _read_archive_member(archive_path: Path, name: str) -> bytes | None:
    """Return one in-root archive member payload, or None on failure."""
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                return archive.read(name)
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as archive:
                extracted = archive.extractfile(name)
                if extracted is None:
                    return None
                return extracted.read()
    except (OSError, KeyError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return None
    return None


def _extract_archive_member(
    archive_path: Path, name: str, extract_root: Path
) -> None:
    """Write one in-root member under ``extract_root`` without following links."""
    dest = _bounded_destination(extract_root, name)
    if dest is None:
        return
    try:
        if dest.exists() and (dest.is_symlink() or dest.is_dir()):
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = _read_archive_member(archive_path, name)
        if payload is None:
            return
        dest.write_bytes(payload)
    except OSError:
        return


def _bounded_destination(extract_root: Path, member_name: str) -> Path | None:
    """Return the in-root destination for ``member_name``, or None if unsafe."""
    if _archive_member_escapes(member_name, extract_root):
        return None
    root = extract_root.resolve()
    return Path(os.path.normpath(os.path.join(str(root), member_name.replace("\\", "/"))))


def _archive_traversal_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return traversal findings for zip/tar files inside ``root`` without extracting."""
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        try:
            if path.is_symlink() or not path.is_file() or not _is_archive_path(path):
                continue
        except OSError:
            continue
        member_hits, _safe = _classify_archive_members(path, root)
        hits.extend(member_hits)
    return tuple(hits)


def _ratio_is_bomb(uncompressed: int, compressed: int) -> bool:
    """Return whether uncompressed/compressed exceeds the bounded ratio.

    Args:
        uncompressed: Claimed uncompressed member size in bytes.
        compressed: Stored compressed size in bytes.

    Returns:
        True when ``uncompressed`` is positive and the ratio is greater
        than ``_MAX_ARCHIVE_COMPRESSION_RATIO``. Empty members are not
        bombs. A zero compressed size is treated as one byte so a claimed
        payload with no stored bytes still fails closed.
    """
    if uncompressed <= 0:
        return False
    return uncompressed / max(compressed, 1) > _MAX_ARCHIVE_COMPRESSION_RATIO


def _is_archive_member_name(name: str) -> bool:
    """Return whether ``name`` uses a zip or tar suffix."""
    return _archive_kind_from_name(name) is not None


def _archive_kind_from_name(name: str) -> str | None:
    """Return ``zip`` or ``tar`` from a member or file name suffix."""
    lowered = name.lower().replace("\\", "/")
    if lowered.endswith(".zip"):
        return "zip"
    if lowered.endswith(_ARCHIVE_SUFFIXES):
        return "tar"
    return None


def _decompression_bomb_hit(archive_file: str, member_name: str) -> PluginHit:
    """Return one decompression-bomb finding with a sanitized path label."""
    return PluginHit(
        rule_id="claude-plugin-decompression-bomb",
        line=1,
        snippet=_sanitize_path_snippet(member_name),
        message=CLAUDE_PLUGIN_DECOMPRESSION_BOMB_MESSAGE,
        file=archive_file,
    )


def _zip_member_is_dir(info: zipfile.ZipInfo) -> bool:
    """Return whether ``info`` is a directory member."""
    name = info.filename
    return info.is_dir() or name.endswith("/") or name.endswith("\\")


def _zip_handle_bomb_hits(
    archive: zipfile.ZipFile,
    display_file: str,
    extract_root: Path,
    depth: int,
) -> tuple[PluginHit, ...]:
    """Return bomb hits for one opened zip without writing members."""
    hits: list[PluginHit] = []
    for info in archive.infolist():
        name = info.filename
        if _zip_member_is_dir(info):
            continue
        if _archive_member_escapes(name, extract_root):
            continue
        if _ratio_is_bomb(info.file_size, info.compress_size):
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        if not _is_archive_member_name(name):
            continue
        nested_depth = depth + 1
        if nested_depth > _MAX_ARCHIVE_NESTING_DEPTH:
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        if info.file_size > _MAX_PACKAGE_BYTES:
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        try:
            payload = archive.read(name)
        except (OSError, KeyError, RuntimeError, zipfile.BadZipFile, ValueError):
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        hits.extend(
            _inspect_archive_bytes_decompression_bombs(
                payload,
                display_file=display_file,
                member_name=name,
                extract_root=extract_root,
                depth=nested_depth,
            )
        )
    return tuple(hits)


def _tar_handle_bomb_hits(
    archive: tarfile.TarFile,
    display_file: str,
    extract_root: Path,
    depth: int,
    compressed_size: int,
) -> tuple[PluginHit, ...]:
    """Return bomb hits for one opened tar without writing members."""
    hits: list[PluginHit] = []
    for member in archive.getmembers():
        if not member.isfile():
            continue
        name = member.name
        if _archive_member_escapes(name, extract_root):
            continue
        if _ratio_is_bomb(member.size, compressed_size):
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        if not _is_archive_member_name(name):
            continue
        nested_depth = depth + 1
        if nested_depth > _MAX_ARCHIVE_NESTING_DEPTH:
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        if member.size > _MAX_PACKAGE_BYTES:
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        try:
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            payload = extracted.read()
        except (OSError, tarfile.TarError, ValueError):
            hits.append(_decompression_bomb_hit(display_file, name))
            continue
        hits.extend(
            _inspect_archive_bytes_decompression_bombs(
                payload,
                display_file=display_file,
                member_name=name,
                extract_root=extract_root,
                depth=nested_depth,
            )
        )
    return tuple(hits)


def _inspect_archive_bytes_decompression_bombs(
    payload: bytes,
    *,
    display_file: str,
    member_name: str,
    extract_root: Path,
    depth: int,
) -> tuple[PluginHit, ...]:
    """Inspect nested archive bytes in memory without writing the payload."""
    kind = _archive_kind_from_name(member_name)
    buffer = io.BytesIO(payload)
    try:
        if kind == "zip":
            with zipfile.ZipFile(buffer) as archive:
                return _zip_handle_bomb_hits(archive, display_file, extract_root, depth)
        if kind == "tar":
            with tarfile.open(fileobj=buffer, mode="r:*") as archive:
                return _tar_handle_bomb_hits(
                    archive, display_file, extract_root, depth, len(payload)
                )
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return (_decompression_bomb_hit(display_file, member_name),)
    return ()


def _inspect_archive_decompression_bombs(
    archive_path: Path,
    extract_root: Path,
    *,
    depth: int = 0,
) -> tuple[PluginHit, ...]:
    """Inspect one archive path for ratio or nesting bombs without extracting."""
    try:
        if archive_path.is_symlink() or not archive_path.is_file():
            return ()
    except OSError:
        return ()
    relative = _archive_display_path(archive_path, extract_root)
    kind = _archive_kind_from_name(archive_path.name)
    try:
        if kind == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                return _zip_handle_bomb_hits(archive, relative, extract_root, depth)
        if kind == "tar":
            compressed_size = archive_path.stat().st_size
            with tarfile.open(archive_path) as archive:
                return _tar_handle_bomb_hits(
                    archive, relative, extract_root, depth, compressed_size
                )
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return ()
    return ()


def _decompression_bomb_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return decompression-bomb findings for zip/tar files inside ``root``.

    Args:
        root: Materialized plugin tree.

    Returns:
        Hits for members whose uncompressed/compressed ratio exceeds
        ``_MAX_ARCHIVE_COMPRESSION_RATIO`` or whose nested zip/tar depth
        exceeds ``_MAX_ARCHIVE_NESTING_DEPTH``. Path-traversal members stay
        the traversal class. Oversized file-count or byte-count trees stay
        the oversized class. Snippets are path labels; payloads are not
        extracted.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        try:
            if path.is_symlink() or not path.is_file() or not _is_archive_path(path):
                continue
        except OSError:
            continue
        hits.extend(_inspect_archive_decompression_bombs(path, root))
    return tuple(hits)


def _unadmitted_submodule_hits(
    root: Path, *, _seen: frozenset[Path] | None = None
) -> tuple[PluginHit, ...]:
    """Return findings for nested git pointers without admitted SHA identity."""
    try:
        resolved = root.resolve()
    except OSError:
        resolved = root
    seen = set(_seen or ())
    if resolved in seen:
        return ()
    seen.add(resolved)
    hits: list[PluginHit] = []
    for pointer in _iter_submodules(root):
        if not _submodule_is_admitted(root, pointer):
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-unadmitted-submodule",
                    line=1,
                    snippet=_sanitize_path_snippet(pointer.path or pointer.file),
                    message=CLAUDE_PLUGIN_UNADMITTED_SUBMODULE_MESSAGE,
                    file=pointer.file,
                )
            )
            continue
        hits.extend(
            _unadmitted_submodule_hits(root / pointer.path, _seen=frozenset(seen))
        )
    return tuple(hits)


def _iter_submodules(root: Path) -> tuple[_SubmodulePointer, ...]:
    """Discover .gitmodules entries and nested gitlink directories."""
    found: dict[str, _SubmodulePointer] = {}
    gitmodules = root / ".gitmodules"
    try:
        gitmodules_is_symlink = gitmodules.is_symlink()
        gitmodules_is_file = gitmodules.is_file()
    except OSError:
        gitmodules_is_symlink = False
        gitmodules_is_file = False
    if gitmodules_is_symlink:
        found[""] = _SubmodulePointer(path="", file=".gitmodules", recorded_sha="")
    elif gitmodules_is_file:
        for pointer in _parse_gitmodules(gitmodules):
            found[pointer.path] = pointer
    for path in _walk_entries(root):
        if path.name != ".git":
            continue
        try:
            if path.is_symlink() or not path.is_file():
                continue
            nested_root = path.parent
            rel = nested_root.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if rel in {".", ""}:
            continue
        sha = _gitlink_sha(nested_root)
        existing = found.get(rel)
        if existing is None:
            found[rel] = _SubmodulePointer(path=rel, file=rel, recorded_sha=sha)
        elif not existing.recorded_sha and sha:
            found[rel] = _SubmodulePointer(
                path=rel, file=existing.file, recorded_sha=sha
            )
    return tuple(found.values())


def _parse_gitmodules(path: Path) -> tuple[_SubmodulePointer, ...]:
    """Parse submodule path/url records; fail closed on unreadable INI."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return (_SubmodulePointer(path="", file=".gitmodules", recorded_sha=""),)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return (_SubmodulePointer(path="", file=".gitmodules", recorded_sha=""),)
    pointers: list[_SubmodulePointer] = []
    for section in parser.sections():
        if not section.lower().startswith("submodule"):
            continue
        sub_path = parser.get(section, "path", fallback="").strip()
        if not sub_path:
            sub_path = section.split(None, 1)[-1].strip().strip('"')
        sha = (
            parser.get(section, "sha", fallback="")
            or parser.get(section, "commit", fallback="")
        ).strip()
        pointers.append(
            _SubmodulePointer(path=sub_path, file=".gitmodules", recorded_sha=sha)
        )
    return tuple(pointers)


def _read_head_sha(gitdir: Path) -> str:
    """Return a 40-character SHA from ``gitdir/HEAD``, else empty."""
    head = gitdir / "HEAD"
    try:
        if head.is_symlink() or not head.is_file():
            return ""
        text = head.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return text if _FULL_SHA.fullmatch(text) else ""


def _gitlink_sha(nested_root: Path) -> str:
    """Return the recorded gitlink SHA for ``nested_root``, if present."""
    git_path = nested_root / ".git"
    try:
        if git_path.is_symlink():
            return ""
        if git_path.is_file():
            text = git_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("gitdir:"):
                    spec = stripped.split(":", 1)[1].strip()
                    gitdir = Path(spec)
                    if not gitdir.is_absolute():
                        gitdir = nested_root / spec
                    return _read_head_sha(gitdir)
                if _FULL_SHA.fullmatch(stripped):
                    return stripped
        if git_path.is_dir():
            return _read_head_sha(git_path)
    except (OSError, UnicodeDecodeError):
        return ""
    return ""


def _recorded_sha(root: Path, pointer: _SubmodulePointer) -> str:
    """Return a full SHA from gitmodules, gitlink file, or gitdir HEAD."""
    if _FULL_SHA.fullmatch(pointer.recorded_sha):
        return pointer.recorded_sha
    nested = root / pointer.path
    try:
        if nested.is_symlink():
            return ""
        if nested.is_file():
            body = nested.read_text(encoding="utf-8").strip()
            return body if _FULL_SHA.fullmatch(body) else ""
        if nested.is_dir():
            sha = _gitlink_sha(nested)
            return sha if _FULL_SHA.fullmatch(sha) else ""
    except (OSError, UnicodeDecodeError):
        return ""
    return ""


def _submodule_is_admitted(root: Path, pointer: _SubmodulePointer) -> bool:
    """Return whether a nested pointer has a complete admitted package identity."""
    if not pointer.path or pointer.path in {".", ".."}:
        return False
    parts = Path(pointer.path.replace("\\", "/")).parts
    if ".." in parts or pointer.path.startswith("/") or _WINDOWS_DRIVE.match(pointer.path):
        return False
    sha = _recorded_sha(root, pointer)
    if not sha:
        return False
    nested = root / pointer.path
    try:
        if nested.is_symlink() or not nested.is_dir():
            return False
    except OSError:
        return False
    if _license_summary(nested) == "absent":
        return False
    identity = _plugin_identity(nested)
    nested_sha = identity["source_commit_sha"]
    if not _FULL_SHA.fullmatch(nested_sha or ""):
        return False
    if nested_sha.lower() != sha.lower():
        return False
    plugin_dir = nested / ".claude-plugin"
    try:
        if not plugin_dir.is_dir() or plugin_dir.is_symlink():
            return False
    except OSError:
        return False
    return True
