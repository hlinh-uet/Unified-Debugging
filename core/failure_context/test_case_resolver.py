"""Resolve project-specific tests into one shared, provenance-rich contract."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import shlex
from functools import lru_cache
from typing import Any, Dict, Iterable, List

from .utils import clip


RESOLVED_TEST_CASE_SCHEMA = "unified_debugging.resolved_test_case.v1"
FILE_PREVIEW_BYTES = 512
INLINE_CONTENT_LIMIT = 12_000

_INLINE_INPUT_FIELDS = (
    "test_input",
    "input",
    "input_data",
    "stdin",
    "stdin_data",
)
_ARGUMENT_FIELDS = ("arguments", "args")
_INPUT_FILE_FIELDS = (
    "input_file",
    "stdin_file",
    "test_input_file",
)


class TestCaseResolver:
    """Capability interface for adding a test format without changing agents."""

    name = "base"

    def resolve(
        self,
        *,
        bug: Any,
        record: Dict[str, Any],
        test_id: str,
        root: str,
    ) -> Dict[str, Any]:
        raise NotImplementedError


class ExplicitMetadataResolver(TestCaseResolver):
    name = "explicit_metadata"

    def resolve(
        self,
        *,
        bug: Any,
        record: Dict[str, Any],
        test_id: str,
        root: str,
    ) -> Dict[str, Any]:
        del bug
        inputs = []
        for field in _INLINE_INPUT_FIELDS:
            value = record.get(field)
            if value in (None, "", [], {}):
                continue
            inputs.append(_inline_input(
                value,
                role="primary_input",
                kind="metadata_input",
                selection_basis=f"test_record.{field}",
                primary=not inputs,
            ))
        for field in _INPUT_FILE_FIELDS:
            path = _safe_repo_file(str(record.get(field) or ""), root)
            if not path:
                continue
            inputs.append(_file_artifact(
                path,
                root=root,
                role="primary_input",
                selection_basis=f"test_record.{field}",
                primary=not inputs,
            ))
        for field in _ARGUMENT_FIELDS:
            value = record.get(field)
            if value in (None, "", [], {}):
                continue
            inputs.append(_inline_input(
                value,
                role="arguments",
                kind="metadata_arguments",
                selection_basis=f"test_record.{field}",
                primary=not inputs,
            ))
        if not inputs:
            return {}
        return _resolved_case(
            test_id=test_id,
            framework="explicit_metadata",
            inputs=inputs,
            oracle={},
            definition={},
            execution={},
            resolver=self.name,
        )


class TcpdumpTestListResolver(TestCaseResolver):
    name = "tcpdump_testlist"

    def resolve(
        self,
        *,
        bug: Any,
        record: Dict[str, Any],
        test_id: str,
        root: str,
    ) -> Dict[str, Any]:
        del record
        raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
        candidates = [
            str(value)
            for value in raw.get("test_files") or []
            if os.path.basename(str(value)) == "TESTLIST"
        ]
        candidates.append("tests/TESTLIST")
        manifest = next(
            (
                path
                for value in dict.fromkeys(candidates)
                for path in [_safe_repo_file(value, root)]
                if path
            ),
            "",
        )
        if not manifest:
            return {}
        matches = []
        try:
            with open(
                manifest,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as stream:
                for number, line in enumerate(stream, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    try:
                        fields = shlex.split(stripped, comments=True)
                    except ValueError:
                        continue
                    if len(fields) >= 3 and fields[0] == test_id:
                        matches.append((number, line.rstrip("\n"), fields))
        except OSError:
            return {}
        if len(matches) != 1:
            return {}
        line_number, source, fields = matches[0]
        manifest_dir = os.path.dirname(manifest)
        input_path = _safe_repo_file(
            os.path.join(
                os.path.relpath(manifest_dir, root),
                fields[1],
            ),
            root,
        )
        oracle_path = _safe_repo_file(
            os.path.join(
                os.path.relpath(manifest_dir, root),
                fields[2],
            ),
            root,
        )
        if not input_path:
            return {}
        input_artifact = _file_artifact(
            input_path,
            root=root,
            role="primary_input",
            selection_basis="tcpdump_testlist.input",
            primary=True,
        )
        input_artifact["kind"] = (
            "binary_pcap"
            if input_path.lower().endswith((".pcap", ".cap"))
            else input_artifact["kind"]
        )
        oracle = (
            _oracle_file(
                oracle_path,
                root=root,
                kind="expected_output_file",
                selection_basis="tcpdump_testlist.output",
            )
            if oracle_path
            else {}
        )
        return _resolved_case(
            test_id=test_id,
            framework="tcpdump_testlist",
            definition={
                "kind": "manifest_entry",
                "source_path": manifest,
                "source_range": {
                    "start_line": line_number,
                    "end_line": line_number,
                },
                "source": source,
            },
            execution={
                "runner": "tests/TESTonce",
                "cwd": os.path.relpath(manifest_dir, root),
                "executable_hint": "tcpdump",
                "arguments": fields[3:],
            },
            inputs=[input_artifact],
            oracle=oracle,
            resolver=self.name,
        )


class PhptTestResolver(TestCaseResolver):
    name = "phpt"

    def resolve(
        self,
        *,
        bug: Any,
        record: Dict[str, Any],
        test_id: str,
        root: str,
    ) -> Dict[str, Any]:
        del bug, record
        relative = test_id if test_id.endswith(".phpt") else test_id + ".phpt"
        path = _safe_repo_file(relative, root)
        if not path:
            return {}
        try:
            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as stream:
                source = stream.read()
        except OSError:
            return {}
        sections = _phpt_sections(source)
        inputs = []
        if sections.get("FILE"):
            inputs.append(_inline_input(
                sections["FILE"],
                role="primary_input",
                kind="php_source",
                selection_basis="phpt.FILE",
                primary=True,
                source_path=path,
                media_type="application/x-httpd-php",
            ))
        elif sections.get("FILE_EXTERNAL"):
            external = _safe_repo_file(
                os.path.join(
                    os.path.relpath(os.path.dirname(path), root),
                    sections["FILE_EXTERNAL"].strip(),
                ),
                root,
            )
            if external:
                inputs.append(_file_artifact(
                    external,
                    root=root,
                    role="primary_input",
                    selection_basis="phpt.FILE_EXTERNAL",
                    primary=True,
                ))
        section_roles = {
            "ARGS": "arguments",
            "INI": "configuration",
            "ENV": "environment",
            "GET": "request_query",
            "POST": "request_body",
            "POST_RAW": "request_body",
            "COOKIE": "request_cookie",
            "STDIN": "stdin",
        }
        for section, role in section_roles.items():
            value = sections.get(section)
            if value is None or value == "":
                continue
            inputs.append(_inline_input(
                value,
                role=role,
                kind="phpt_section",
                selection_basis=f"phpt.{section}",
                primary=not inputs,
                source_path=path,
            ))
        oracle = {}
        for section, kind in (
            ("EXPECT", "phpt_expect"),
            ("EXPECTF", "phpt_expect_format"),
            ("EXPECTREGEX", "phpt_expect_regex"),
        ):
            if section in sections:
                oracle = {
                    "kind": kind,
                    "selection_basis": f"phpt.{section}",
                    "source_path": path,
                    "source": clip(
                        sections.get(section),
                        INLINE_CONTENT_LIMIT,
                    ),
                }
                break
        if not oracle and sections.get("EXPECT_EXTERNAL"):
            external = _safe_repo_file(
                os.path.join(
                    os.path.relpath(os.path.dirname(path), root),
                    sections["EXPECT_EXTERNAL"].strip(),
                ),
                root,
            )
            if external:
                oracle = _oracle_file(
                    external,
                    root=root,
                    kind="phpt_expect_external",
                    selection_basis="phpt.EXPECT_EXTERNAL",
                )
        return _resolved_case(
            test_id=test_id,
            framework="phpt",
            definition={
                "kind": "phpt_file",
                "source_path": path,
                "source_range": {},
                "source": clip(source, INLINE_CONTENT_LIMIT),
            },
            execution={
                "runner": "run-tests.php",
                "cwd": ".",
                "executable_hint": "sapi/cli/php",
                "arguments": [],
            },
            inputs=inputs,
            oracle=oracle,
            resolver=self.name,
        )


DEFAULT_TEST_CASE_RESOLVERS = (
    TcpdumpTestListResolver(),
    PhptTestResolver(),
    ExplicitMetadataResolver(),
)


def resolve_test_case(
    *,
    bug: Any,
    record: Dict[str, Any],
    test_id: str,
    root: str,
    resolvers: Iterable[TestCaseResolver] = DEFAULT_TEST_CASE_RESOLVERS,
) -> Dict[str, Any]:
    """Return the first exact resolver result; never guess among ambiguities."""
    for resolver in resolvers:
        resolved = resolver.resolve(
            bug=bug,
            record=record,
            test_id=test_id,
            root=root,
        )
        if resolved:
            return resolved
    return {}


def source_test_case(
    *,
    test_id: str,
    source_match: Dict[str, Any],
) -> Dict[str, Any]:
    """Expose the existing source-test path through the same additive contract."""
    if not source_match:
        return {}
    return _resolved_case(
        test_id=test_id,
        framework="source_test",
        definition={
            "kind": "source_test_definition",
            "source_path": source_match.get("source_path") or "",
            "source_range": source_match.get("source_range") or {},
            "source": clip(
                source_match.get("source"),
                INLINE_CONTENT_LIMIT,
            ),
        },
        execution={},
        inputs=[],
        oracle={},
        resolver="source_test_definition",
    )


def _resolved_case(
    *,
    test_id: str,
    framework: str,
    definition: Dict[str, Any],
    execution: Dict[str, Any],
    inputs: List[Dict[str, Any]],
    oracle: Dict[str, Any],
    resolver: str,
) -> Dict[str, Any]:
    return {
        "schema": RESOLVED_TEST_CASE_SCHEMA,
        "version": 1,
        "test_id": test_id,
        "framework": framework,
        "definition": definition,
        "execution": execution,
        "inputs": inputs,
        "oracle": oracle,
        "provenance": {
            "resolver": resolver,
            "confidence": "exact",
            "ground_truth_used": False,
        },
        "diagnostics": [],
    }


def _inline_input(
    value: Any,
    *,
    role: str,
    kind: str,
    selection_basis: str,
    primary: bool,
    source_path: str = "",
    media_type: str = "text/plain",
) -> Dict[str, Any]:
    return {
        "role": role,
        "primary": bool(primary),
        "kind": kind,
        "selection_basis": selection_basis,
        "source_path": source_path,
        "source_ranges": [],
        "source": clip(value, INLINE_CONTENT_LIMIT),
        "symbols": [],
        "media_type": media_type,
    }


def _file_artifact(
    path: str,
    *,
    root: str,
    role: str,
    selection_basis: str,
    primary: bool,
) -> Dict[str, Any]:
    try:
        stat = os.stat(path)
        content = _read_file_artifact(
            path,
            int(stat.st_mtime_ns),
            int(stat.st_size),
        )
    except OSError:
        return {}
    preview = content["preview"]
    size = int(stat.st_size)
    digest = str(content["sha256"])
    relative = os.path.relpath(path, root).replace(os.sep, "/")
    media_type = _media_type(path)
    is_binary = bool(content["is_binary"])
    record = {
        "role": role,
        "primary": bool(primary),
        "kind": "binary_fixture" if is_binary else "text_fixture",
        "selection_basis": selection_basis,
        "path": relative,
        "source_path": path,
        "source_ranges": [],
        "source": "",
        "symbols": [],
        "media_type": media_type,
        "sha256": digest,
        "size": int(size),
        "content_ref": f"sha256:{digest}",
    }
    if is_binary:
        record["preview"] = {
            "encoding": "hex",
            "byte_count": len(preview),
            "content": preview.hex(),
            "truncated": size > len(preview),
        }
    else:
        record["source"] = clip(
            content["inline_content"].decode(
                "utf-8",
                errors="replace",
            ),
            INLINE_CONTENT_LIMIT,
        )
        record["preview"] = {
            "encoding": "utf-8",
            "byte_count": len(preview),
            "content": record["source"],
            "truncated": size > len(preview),
        }
    return record


@lru_cache(maxsize=512)
def _read_file_artifact(
    path: str,
    mtime_ns: int,
    size: int,
) -> Dict[str, Any]:
    """Hash an exact fixture once per immutable file revision.

    FailContext may be rebuilt after census, detailed, and recovery traces.
    Keying this bounded cache by path plus stat identity avoids rereading a
    potentially large pcap on every phase while never retaining full content.
    """
    del mtime_ns, size
    digest = hashlib.sha256()
    inline_content = bytearray()
    with open(path, "rb") as stream:
        preview = stream.read(FILE_PREVIEW_BYTES)
        digest.update(preview)
        is_binary = _is_binary(preview, path)
        if not is_binary:
            inline_content.extend(preview)
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if (
                not is_binary
                and len(inline_content) <= INLINE_CONTENT_LIMIT
            ):
                remaining = INLINE_CONTENT_LIMIT + 1 - len(inline_content)
                inline_content.extend(chunk[:remaining])
    return {
        "sha256": digest.hexdigest(),
        "preview": preview,
        "inline_content": bytes(inline_content),
        "is_binary": is_binary,
    }


def _oracle_file(
    path: str,
    *,
    root: str,
    kind: str,
    selection_basis: str,
) -> Dict[str, Any]:
    artifact = _file_artifact(
        path,
        root=root,
        role="expected_oracle",
        selection_basis=selection_basis,
        primary=False,
    )
    if not artifact:
        return {}
    return {
        "kind": kind,
        "selection_basis": selection_basis,
        "path": artifact.get("path") or "",
        "source_path": artifact.get("source_path") or "",
        "source": artifact.get("source") or "",
        "media_type": artifact.get("media_type") or "",
        "sha256": artifact.get("sha256") or "",
        "size": artifact.get("size") or 0,
        "content_ref": artifact.get("content_ref") or "",
        "preview": artifact.get("preview") or {},
    }


def _phpt_sections(source: str) -> Dict[str, str]:
    matches = list(re.finditer(
        r"(?m)^--(?P<name>[A-Z][A-Z0-9_]*)--[ \t]*\r?$",
        str(source or ""),
    ))
    sections = {}
    for index, match in enumerate(matches):
        start = match.end()
        if source[start:start + 2] == "\r\n":
            start += 2
        elif source[start:start + 1] == "\n":
            start += 1
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(source)
        )
        value = source[start:end]
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
        sections[match.group("name")] = value
    return sections


def _safe_repo_file(value: str, root: str) -> str:
    if not value or not root:
        return ""
    candidate = value if os.path.isabs(value) else os.path.join(root, value)
    real = os.path.realpath(candidate)
    real_root = os.path.realpath(root)
    try:
        within = os.path.commonpath([real, real_root]) == real_root
    except ValueError:
        within = False
    return real if within and os.path.isfile(real) else ""


def _media_type(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".pcap", ".cap")):
        return "application/vnd.tcpdump.pcap"
    if lowered.endswith(".phpt"):
        return "application/x-httpd-php-test"
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def _is_binary(preview: bytes, path: str) -> bool:
    if path.lower().endswith((".pcap", ".cap")):
        return True
    if b"\0" in preview:
        return True
    try:
        preview.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False
