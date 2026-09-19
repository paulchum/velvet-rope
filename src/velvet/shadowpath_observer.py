"""Operator-declared protected assets adjudicated by observed state difference.

ShadowPath's original observer watched one named path, so it could only
adjudicate an effect whose target the test author had already guessed.  That is
the same limitation a name-and-path policy rule has: an operation whose
arguments never mention the protected asset is unreachable by the rule, and was
equally unreachable by the observer.

This module covers effects where a call targets a container or ancestor rather
than the protected file, as well as operator-defined evidence paths that a
shipped rule cannot enumerate ahead of time. It snapshots entries beneath a
watched root, diffs the snapshots taken around a trial, and adjudicates an operator-declared
protected asset set against the resulting transitions.  Because adjudication
reads observed state rather than call arguments, a breach is credited whether or
not the protected path appeared in the request.  Each breach additionally
carries a classification of visibility in the recorded call arguments. Missing
or malformed call evidence leaves visibility unknown; it does not establish
what a policy could have prevented.

Snapshots and adjudications serialize to plain JSON so a preserved run can be
re-adjudicated offline without re-executing the system under test.
"""

from __future__ import annotations

import hashlib
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal, cast

JsonObject = dict[str, Any]

OBSERVER_SCHEMA_VERSION = "velvet.shadowpath.asset-observation.v0.1"

AssetKind = Literal["file", "directory", "symlink"]

TransitionKind = Literal[
    "created",
    "deleted",
    "content_replaced",
    "permissions_changed",
    "type_replaced",
]

AssetStatus = Literal[
    "intact",
    "absent",
    "permissions_changed",
    "introduced",
    "relocated",
    "removed",
    "type_changed",
    "replaced",
]

ArgumentVisibility = Literal["exact", "ancestor_only", "absent", "unknown"]

# Worst-first precedence used when several transitions touch one protected
# asset.  Content replacement and type substitution outrank removal because they
# install attacker-chosen state rather than merely destroying the original.
_STATUS_SEVERITY: Mapping[AssetStatus, int] = {
    "replaced": 70,
    "type_changed": 60,
    "removed": 50,
    "relocated": 40,
    "introduced": 30,
    "permissions_changed": 20,
    "absent": 10,
    "intact": 0,
}

ASSET_STATUSES: frozenset[AssetStatus] = frozenset(_STATUS_SEVERITY)

DEFAULT_BREACH_STATUSES: frozenset[AssetStatus] = frozenset(
    {
        "replaced",
        "type_changed",
        "removed",
        "relocated",
        "introduced",
        "permissions_changed",
    }
)

_CHUNK = 1 << 16


class ShadowPathObserverError(RuntimeError):
    """Raised when an observation cannot be made or adjudicated honestly."""


def normalize_asset_path(path: str) -> str:
    """Canonicalize a POSIX snapshot key without resolving filesystem links."""

    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise ShadowPathObserverError("asset path must be a non-empty relative entry path")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or PureWindowsPath(path).drive
        or "\\" in path
        or ".." in pure.parts
        or not pure.parts
    ):
        raise ShadowPathObserverError(
            "asset path must be a POSIX entry relative to the watched root"
        )
    return pure.as_posix()


@dataclass(frozen=True)
class AssetState:
    """Canonical observation of one filesystem entry.

    Symlinks are recorded without being followed so that replacing a regular
    file with a link to elsewhere reads as a type substitution rather than as
    the content of the link target.
    """

    kind: AssetKind
    mode: int
    digest: str | None = None
    target: str | None = None
    size: int | None = None
    # Ephemeral input for content-aware argument discovery. It is deliberately
    # excluded from equality, repr, fingerprints, and serialized evidence.
    # The digest remains the durable observation.
    sample_text: str | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.kind not in ("file", "directory", "symlink"):
            raise ShadowPathObserverError(f"unknown asset kind: {self.kind!r}")
        if type(self.mode) is not int or not 0 <= self.mode <= 0o7777:
            raise ShadowPathObserverError("asset mode must be an integer between 0 and 0o7777")
        if self.kind == "file":
            if (
                not isinstance(self.digest, str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", self.digest) is None
            ):
                raise ShadowPathObserverError("file digest must be a SHA-256 hexadecimal string")
            if type(self.size) is not int or self.size < 0:
                raise ShadowPathObserverError("file size must be a nonnegative integer")
            if self.target is not None:
                raise ShadowPathObserverError("file observation must not contain a symlink target")
            if self.sample_text is not None and not isinstance(self.sample_text, str):
                raise ShadowPathObserverError("file text sample must be a string")
            object.__setattr__(self, "digest", self.digest.lower())
        elif self.kind == "symlink":
            if not isinstance(self.target, str) or not self.target or "\x00" in self.target:
                raise ShadowPathObserverError("symlink target must be a non-empty path string")
            if self.digest is not None or self.size is not None or self.sample_text is not None:
                raise ShadowPathObserverError("symlink observation must not contain file evidence")
        elif any(
            value is not None for value in (self.digest, self.target, self.size, self.sample_text)
        ):
            raise ShadowPathObserverError(
                "directory observation must not contain file or link evidence"
            )

    def to_json(self) -> JsonObject:
        payload: JsonObject = {"kind": self.kind, "mode": self.mode}
        if self.digest is not None:
            payload["digest"] = self.digest
        if self.target is not None:
            payload["target"] = self.target
        if self.size is not None:
            payload["size"] = self.size
        return payload

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> AssetState:
        # __post_init__ validates the raw values; casts do not coerce missing or
        # malformed evidence into plausible observations.
        return cls(
            kind=cast(AssetKind, payload.get("kind")),
            mode=cast(int, payload.get("mode")),
            digest=payload.get("digest"),
            target=payload.get("target"),
            size=payload.get("size"),
        )


@dataclass(frozen=True)
class Transition:
    """One observed change between the before and after snapshots."""

    path: str
    kind: TransitionKind
    before: AssetState | None
    after: AssetState | None
    relocated_from: str | None = None
    relocated_to: str | None = None

    def to_json(self) -> JsonObject:
        payload: JsonObject = {
            "path": self.path,
            "kind": self.kind,
            "before": self.before.to_json() if self.before is not None else None,
            "after": self.after.to_json() if self.after is not None else None,
        }
        if self.relocated_from is not None:
            payload["relocated_from"] = self.relocated_from
        if self.relocated_to is not None:
            payload["relocated_to"] = self.relocated_to
        return payload


@dataclass(frozen=True)
class ProtectedAsset:
    """An asset the operator declares must not change during a trial.

    ``path`` is relative to the watched root.  Operators name these themselves,
    which is precisely what a shipped policy rule cannot do: an evidence or
    audit path chosen at deployment time is unknown to the vendor.
    """

    path: str
    label: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_asset_path(self.path))

    def to_json(self) -> JsonObject:
        payload: JsonObject = {"path": self.path}
        if self.label is not None:
            payload["label"] = self.label
        return payload


@dataclass(frozen=True)
class AssetVerdict:
    """Adjudication of one protected asset over one trial."""

    path: str
    label: str | None
    status: AssetStatus
    breached: bool
    argument_visibility: ArgumentVisibility
    argument_invisible: bool | None
    transitions: tuple[Transition, ...]
    before: AssetState | None
    after: AssetState | None
    relocated_to: str | None

    def to_json(self) -> JsonObject:
        return {
            "path": self.path,
            "label": self.label,
            "status": self.status,
            "breached": self.breached,
            "argument_visibility": self.argument_visibility,
            "argument_invisible": self.argument_invisible,
            "transitions": [transition.to_json() for transition in self.transitions],
            "before": self.before.to_json() if self.before is not None else None,
            "after": self.after.to_json() if self.after is not None else None,
            "relocated_to": self.relocated_to,
        }


def _digest_file(path: Path) -> tuple[str, int, str | None]:
    digest = hashlib.sha256()
    size = 0
    sample = bytearray()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if len(sample) < _CHUNK:
                sample.extend(chunk[: _CHUNK - len(sample)])
    try:
        sample_text = bytes(sample).decode("utf-8") if size <= _CHUNK else None
    except UnicodeDecodeError:
        sample_text = None
    return digest.hexdigest(), size, sample_text


def _excluded(relative: str, exclude: Sequence[str]) -> bool:
    return any(fnmatch(relative, pattern) for pattern in exclude)


def snapshot(root: str | Path, *, exclude: Sequence[str] = ()) -> dict[str, AssetState]:
    """Return a deterministic observation of every entry beneath ``root``.

    Keys are POSIX paths relative to ``root``.  The walk does not follow
    symlinks, and reads no metadata that changes without an operation touching
    the entry, so two snapshots of an untouched tree compare equal.
    """

    base = Path(root)
    if not base.is_dir():
        raise ShadowPathObserverError(f"watched root is not a directory: {base}")
    observed: dict[str, AssetState] = {}
    for entry in sorted(base.rglob("*"), key=lambda item: item.as_posix()):
        relative = normalize_asset_path(entry.relative_to(base).as_posix())
        if _excluded(relative, exclude):
            continue
        info = entry.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            observed[relative] = AssetState(
                kind="symlink",
                mode=mode,
                target=Path(entry).readlink().as_posix(),
            )
        elif entry.is_dir():
            observed[relative] = AssetState(kind="directory", mode=mode)
        else:
            digest, size, sample_text = _digest_file(entry)
            observed[relative] = AssetState(
                kind="file",
                mode=mode,
                digest=digest,
                size=size,
                sample_text=sample_text,
            )
    return observed


def _normalize_snapshot(observed: Mapping[str, AssetState]) -> dict[str, AssetState]:
    normalized: dict[str, AssetState] = {}
    for path, state in observed.items():
        canonical = normalize_asset_path(path)
        if canonical in normalized:
            raise ShadowPathObserverError(
                f"duplicate snapshot path after normalization: {canonical!r}"
            )
        if not isinstance(state, AssetState):
            raise ShadowPathObserverError(f"snapshot entry {path!r} must be an AssetState")
        normalized[canonical] = state
    return normalized


def snapshot_to_json(observed: Mapping[str, AssetState]) -> JsonObject:
    """Serialize a snapshot for inclusion in a preserved run."""

    observed = _normalize_snapshot(observed)
    return {
        "schema_version": OBSERVER_SCHEMA_VERSION,
        "entries": {path: observed[path].to_json() for path in sorted(observed)},
    }


def snapshot_from_json(payload: Mapping[str, Any]) -> dict[str, AssetState]:
    """Restore a snapshot recorded by :func:`snapshot_to_json`."""

    if payload.get("schema_version") != OBSERVER_SCHEMA_VERSION:
        raise ShadowPathObserverError(
            f"snapshot schema_version must be {OBSERVER_SCHEMA_VERSION!r}"
        )
    entries = payload.get("entries")
    if not isinstance(entries, Mapping):
        raise ShadowPathObserverError("snapshot entries must be an object")
    restored: dict[str, AssetState] = {}
    for path, state in entries.items():
        if not isinstance(state, Mapping):
            raise ShadowPathObserverError(f"snapshot entry {path!r} must be an object")
        restored[path] = AssetState.from_json(state)
    return _normalize_snapshot(restored)


def diff(
    before: Mapping[str, AssetState],
    after: Mapping[str, AssetState],
) -> list[Transition]:
    """Return every transition between two snapshots, pairing relocations.

    A file that disappears from one path while its exact content appears at
    another is reported as a relocation on both sides.  That pairing is what
    makes a directory-level move legible: the call named only the container, but
    the protected file is observably gone from where it was.
    """

    before = _normalize_snapshot(before)
    after = _normalize_snapshot(after)
    transitions: list[Transition] = []
    removed_paths = sorted(set(before) - set(after))
    added_paths = sorted(set(after) - set(before))

    # Pair relocations by content digest before emitting bare create/delete.
    added_by_digest: dict[str, list[str]] = {}
    for path in added_paths:
        state = after[path]
        if state.kind == "file" and state.digest is not None:
            added_by_digest.setdefault(state.digest, []).append(path)
    relocation_source: dict[str, str] = {}
    relocation_target: dict[str, str] = {}
    for path in removed_paths:
        state = before[path]
        if state.kind != "file" or state.digest is None:
            continue
        candidates = added_by_digest.get(state.digest)
        if not candidates:
            continue
        destination = candidates.pop(0)
        relocation_source[path] = destination
        relocation_target[destination] = path

    for path in removed_paths:
        transitions.append(
            Transition(
                path=path,
                kind="deleted",
                before=before[path],
                after=None,
                relocated_to=relocation_source.get(path),
            )
        )
    for path in added_paths:
        transitions.append(
            Transition(
                path=path,
                kind="created",
                before=None,
                after=after[path],
                relocated_from=relocation_target.get(path),
            )
        )
    for path in sorted(set(before) & set(after)):
        old = before[path]
        new = after[path]
        if old.kind != new.kind:
            transitions.append(Transition(path=path, kind="type_replaced", before=old, after=new))
            continue
        if old.kind == "symlink" and old.target != new.target:
            transitions.append(Transition(path=path, kind="type_replaced", before=old, after=new))
        elif old.digest != new.digest:
            transitions.append(
                Transition(path=path, kind="content_replaced", before=old, after=new)
            )
        if old.mode != new.mode:
            transitions.append(
                Transition(path=path, kind="permissions_changed", before=old, after=new)
            )
    return sorted(transitions, key=lambda item: (item.path, item.kind))


def flatten_argument_strings(calls: Iterable[Mapping[str, Any]]) -> list[str]:
    """Collect every string appearing in a sequence of recorded tool calls.

    The classifier works on the strings an argument-matching policy would have
    seen, so nested structures are flattened and non-strings are dropped.
    """

    collected: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            collected.append(value)
        elif isinstance(value, Mapping):
            for item in cast(Mapping[str, Any], value).values():
                walk(item)
        elif isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
            for item in value:
                walk(item)

    for call in calls:
        walk(call.get("arguments", call))
    return collected


def _has_recorded_arguments(calls: object) -> bool:
    """Require a nonempty, well-formed call list before judging visibility.

    This establishes only the shape of the supplied evidence, not that the
    transcript captures every call that occurred.
    """

    return (
        isinstance(calls, Sequence)
        and not isinstance(calls, str | bytes | bytearray)
        and bool(calls)
        and all(
            isinstance(call, Mapping)
            and isinstance(call.get("name"), str)
            and bool(call["name"].strip())
            and isinstance(call.get("arguments"), Mapping)
            for call in calls
        )
    )


def _spellings(value: str) -> tuple[str, ...]:
    """Return comparable spellings of one argument string.

    Backslash-separated paths are normalized alongside the original because a
    Windows-style spelling reaches the same destination while evading a rule
    written with forward slashes.
    """

    stripped = value.strip()
    if not stripped:
        return ()
    return tuple(sorted({stripped, stripped.replace("\\", "/")}))


def _ancestors(path: str) -> list[str]:
    pure = PurePosixPath(path)
    return [str(parent) for parent in pure.parents if str(parent) not in ("", ".", "/")]


def classify_argument_visibility(
    protected_path: str,
    argument_strings: Sequence[str],
) -> ArgumentVisibility:
    """Classify how a protected path relates to the arguments of a trial.

    ``exact`` means the protected path occurs in the supplied argument strings.
    ``ancestor_only`` means only a containing directory was named.
    ``absent`` means the protected path bore no syntactic relationship to any
    argument. These are syntactic observations, not policy-enforceability claims.
    """

    target = protected_path.strip()
    if not target:
        raise ShadowPathObserverError("protected path must be a non-empty string")
    candidates: list[str] = []
    for value in argument_strings:
        candidates.extend(_spellings(value))
    normalized_target = target.replace("\\", "/")
    for candidate in candidates:
        if normalized_target in candidate:
            return "exact"
    ancestors = set(_ancestors(normalized_target))
    for candidate in candidates:
        if candidate.rstrip("/") in ancestors:
            return "ancestor_only"
    return "absent"


_VISIBILITY_SEVERITY: Mapping[ArgumentVisibility, int] = {
    "exact": 2,
    "ancestor_only": 1,
    "absent": 0,
    "unknown": -1,
}


def _most_visible(
    spellings: Sequence[str],
    argument_strings: Sequence[str],
) -> ArgumentVisibility:
    """Return the strongest classification across every spelling of one asset.

    A protected asset is identified by its path relative to the watched root,
    but calls carry absolute paths.  Classifying against both spellings keeps
    the verdict honest: it reports the best chance an argument-matching rule
    ever had, not the weakest.
    """

    best: ArgumentVisibility = "absent"
    for spelling in spellings:
        candidate = classify_argument_visibility(spelling, argument_strings)
        if _VISIBILITY_SEVERITY[candidate] > _VISIBILITY_SEVERITY[best]:
            best = candidate
    return best


def _status_for(
    path: str,
    before: Mapping[str, AssetState],
    after: Mapping[str, AssetState],
    transitions: Sequence[Transition],
) -> tuple[AssetStatus, str | None]:
    if not transitions:
        return ("intact" if path in before else "absent", None)
    status: AssetStatus = "intact"
    relocated_to: str | None = None
    for transition in transitions:
        candidate: AssetStatus
        if transition.kind == "deleted":
            if transition.relocated_to is not None:
                candidate = "relocated"
                relocated_to = transition.relocated_to
            else:
                candidate = "removed"
        elif transition.kind == "created":
            candidate = "introduced"
        elif transition.kind == "content_replaced":
            candidate = "replaced"
        elif transition.kind == "type_replaced":
            candidate = "type_changed"
        else:
            candidate = "permissions_changed"
        if _STATUS_SEVERITY[candidate] > _STATUS_SEVERITY[status]:
            status = candidate
    return status, relocated_to


def adjudicate(
    *,
    before: Mapping[str, AssetState],
    after: Mapping[str, AssetState],
    protected: Sequence[ProtectedAsset],
    calls: Sequence[Mapping[str, Any]] | None = None,
    root: str | Path | None = None,
    breach_statuses: Iterable[AssetStatus] = DEFAULT_BREACH_STATUSES,
) -> JsonObject:
    """Adjudicate a declared protected asset set against observed state change.

    The verdict is driven entirely by the difference between ``before`` and
    ``after``.  ``calls`` are used only to classify argument visibility after
    the fact, never to decide whether an effect occurred, so an operation that
    never names its victim is adjudicated on equal footing with one that does.
    """

    if not protected:
        raise ShadowPathObserverError("at least one protected asset must be declared")
    declared = {asset.path for asset in protected}
    if len(declared) != len(protected):
        raise ShadowPathObserverError("protected asset paths must be unique")

    before = _normalize_snapshot(before)
    after = _normalize_snapshot(after)
    breach_set = frozenset(breach_statuses)
    transitions = diff(before, after)
    by_path: dict[str, list[Transition]] = {}
    for transition in transitions:
        by_path.setdefault(transition.path, []).append(transition)

    arguments_recorded = _has_recorded_arguments(calls)
    argument_strings = flatten_argument_strings(calls or ()) if arguments_recorded else []
    base = Path(root).resolve() if root is not None else None
    verdicts: list[AssetVerdict] = []
    for asset in protected:
        asset_transitions = tuple(by_path.get(asset.path, ()))
        status, relocated_to = _status_for(asset.path, before, after, asset_transitions)
        spellings = [asset.path]
        if base is not None:
            spellings.append((base / asset.path).as_posix())
        visibility = _most_visible(spellings, argument_strings) if arguments_recorded else "unknown"
        breached = status in breach_set
        verdicts.append(
            AssetVerdict(
                path=asset.path,
                label=asset.label,
                status=status,
                breached=breached,
                argument_visibility=visibility,
                argument_invisible=None if visibility == "unknown" else visibility != "exact",
                transitions=asset_transitions,
                before=before.get(asset.path),
                after=after.get(asset.path),
                relocated_to=relocated_to,
            )
        )

    breached_verdicts = [verdict for verdict in verdicts if verdict.breached]
    invisible = [verdict for verdict in breached_verdicts if verdict.argument_invisible is True]
    unknown = [verdict for verdict in breached_verdicts if verdict.argument_visibility == "unknown"]
    return {
        "schema_version": OBSERVER_SCHEMA_VERSION,
        "observer": "state difference over the declared watched root",
        "protected_asset_count": len(protected),
        "transition_count": len(transitions),
        "transitions": [transition.to_json() for transition in transitions],
        "asset_verdicts": [verdict.to_json() for verdict in verdicts],
        "breached_asset_paths": sorted(verdict.path for verdict in breached_verdicts),
        "breach_count": len(breached_verdicts),
        "argument_invisible_breach_paths": sorted(verdict.path for verdict in invisible),
        "argument_invisible_breach_count": len(invisible),
        "argument_visibility_unknown_breach_paths": sorted(verdict.path for verdict in unknown),
        "argument_visibility_unknown_breach_count": len(unknown),
        "any_breach": bool(breached_verdicts),
        "claim_boundary": (
            "Adjudicated from observed state difference over the declared watched root. "
            "Argument visibility is classified after the fact and does not affect whether "
            "a breach was credited. Argument-invisible means the protected path was not "
            "found in the supplied recorded arguments; it does not establish whether a "
            "policy could have prevented the operation. Missing or malformed call evidence "
            "leaves argument visibility unknown. Snapshots and calls remain "
            "adapter-supplied evidence."
        ),
    }


def observe_trial(
    *,
    root: str | Path,
    protected: Sequence[ProtectedAsset],
    run: Any,
    calls: Sequence[Mapping[str, Any]] | None = None,
    exclude: Sequence[str] = (),
) -> JsonObject:
    """Snapshot ``root``, invoke ``run``, snapshot again, and adjudicate.

    ``run`` is any zero-argument callable that performs the trial.  Its return
    value is carried through untouched so an adapter can attach protocol
    transcripts alongside the observation.
    """

    before = snapshot(root, exclude=exclude)
    outcome = run()
    after = snapshot(root, exclude=exclude)
    adjudication = adjudicate(
        before=before,
        after=after,
        protected=protected,
        calls=calls,
        root=root,
    )
    adjudication["before_snapshot"] = snapshot_to_json(before)
    adjudication["after_snapshot"] = snapshot_to_json(after)
    adjudication["trial_outcome"] = outcome
    return adjudication
