"""Private, restart-safe checkpoints for a single confirmed hosted setup.

This journal is a recovery hint, never an authentication or authorization
source. Callers must revalidate hosted policy and saved identities before using
one. An allocation whose response was not checkpointed is deliberately not
retried: the server may already have allocated the workspace or unique name.
"""

import copy
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - explicit fail-closed unsupported host.
    fcntl = None
try:
    import msvcrt
except ImportError:  # pragma: no cover - Windows-only process lock.
    msvcrt = None

try:
    from .terminal_flow import canonical_server_url
except (ImportError, ValueError):
    from terminal_flow import canonical_server_url


MAX_BYTES = 32768
STATES = ("started", "project_created", "identity_registered", "completed")
REQUEST_FIELDS = frozenset({
    "attach_project", "create_project", "role", "lead", "bridge",
    "relationship", "principal_side", "identity_mode", "identity_actor",
    "make_default", "here", "write_instructions", "skip_tools",
    "manage_tools", "actor_id", "actor_type",
})
NETWORK_FIELDS = frozenset({
    "role", "lead", "identity_mode", "identity_actor", "make_default",
    "bridge", "relationship", "principal",
})


class SetupProgressError(RuntimeError):
    """Setup cannot safely begin or resume this local operation."""

    def __init__(self, message):
        super().__init__(message)
        self.journal_path = None
        self.project_id = None
        self.actor_id = None
        self.operation_id = None

    def _with_progress(self, path, record):
        self.journal_path = str(path)
        self.project_id = (record or {}).get("project_id")
        self.actor_id = (record or {}).get("actor_id")
        self.operation_id = (record or {}).get("operation_id")
        self.args = ("%s [journal=%s; project=%s; actor=%s; operation=%s]" % (
            self.args[0], path, self.project_id or "unknown",
            self.actor_id or "unknown", self.operation_id or "unknown"),)
        return self


def _encoded(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise SetupProgressError("setup_progress_invalid: invalid JSON value") from None
    if len(raw) > MAX_BYTES:
        raise SetupProgressError("setup_progress_invalid: record is too large")
    return raw


def _digest(value):
    return hashlib.sha256(_encoded(value)).hexdigest()


def _identifier(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", value):
        raise SetupProgressError("setup_progress_invalid: invalid %s" % label)
    return value


def _check_components(path):
    for part in reversed((path,) + tuple(path.parents)):
        try:
            details = os.lstat(part)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise SetupProgressError("setup_progress_unsafe: symlinked storage")


def _private_directory(path):
    _check_components(path)
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    _check_components(path)
    details = os.lstat(path)
    if not stat.S_ISDIR(details.st_mode) or (os.name != "nt" and stat.S_IMODE(details.st_mode) != 0o700) \
            or (hasattr(os, "getuid") and details.st_uid != os.getuid()):
        raise SetupProgressError("setup_progress_unsafe: storage must be an owned 0700 directory")


def _private_file(details):
    if not stat.S_ISREG(details.st_mode) or (os.name != "nt" and stat.S_IMODE(details.st_mode) != 0o600) \
            or details.st_nlink != 1 \
            or (hasattr(os, "getuid") and details.st_uid != os.getuid()):
        raise SetupProgressError("setup_progress_unsafe: record must be an owned 0600 regular file")
    if details.st_size > MAX_BYTES:
        raise SetupProgressError("setup_progress_invalid: record is too large")


def _read(path):
    _check_components(path)
    try:
        initial = os.lstat(path)
    except FileNotFoundError:
        return None
    _private_file(initial)
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(descriptor)
        _private_file(opened)
        if (initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino):
            raise SetupProgressError("setup_progress_unsafe: record changed while opening")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise SetupProgressError("setup_progress_invalid: record is too large")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (UnicodeError, ValueError):
        raise SetupProgressError("setup_progress_invalid: malformed record") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write(path, record):
    _private_directory(path.parent)
    _check_components(path)
    if path.exists():
        _private_file(os.lstat(path))
    payload = _encoded(record) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".setup-", dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:  # pragma: no cover - Windows exposes chmod(path), not fchmod.
            os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _check_components(path)
        os.replace(temporary, path)
        if os.name != "nt":  # Windows cannot open directories for fsync.
            directory = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class SetupProgress:
    def __init__(self, path, record, resumed):
        self.path = path
        self._record = record
        self.resumed = resumed
        self._active = True

    @property
    def record(self):
        return copy.deepcopy(self._record)

    @property
    def state(self):
        return self._record["state"]

    @property
    def project_id(self):
        return self._record.get("project_id")

    @property
    def actor_id(self):
        return self._record.get("actor_id")

    def _save(self, **changes):
        if not self._active:
            raise SetupProgressError("setup_progress_closed: operation lock is no longer held")
        updated = dict(self._record, **changes)
        _write(self.path, updated)
        self._record = updated

    def before_mutation(self, action):
        allowed_state = {"project_create": "started", "identity_register": "project_created"}.get(action)
        if not allowed_state or self.state != allowed_state or self._record.get("in_flight"):
            raise SetupProgressError("setup_progress_invalid: allocation cannot start in this state")
        self._save(in_flight=action)

    def mutation_rejected(self, action=None):
        """Clear only a definitively rejected request, never a lost response.

        Callers may use this after an explicit HTTP rejection that guarantees
        the allocation did not occur. A timeout, transport disconnect, 5xx, or
        exception after receiving the allocation is not such a guarantee.
        """
        pending = self._record.get("in_flight")
        if not pending or (action is not None and action != pending):
            raise SetupProgressError("setup_progress_invalid: no matching allocation to reject")
        self._save(in_flight=None)

    def network_requested(self, choices):
        """Keep interactive governance choices stable across recovery."""
        choices = _network_choices(choices)
        previous = self._record.get("network_requested")
        if previous is not None and previous != choices:
            raise SetupProgressError("setup_request_conflict: interrupted setup has different confirmed network choices")
        if self.state == "completed":
            raise SetupProgressError("setup_progress_invalid: completed operation cannot change")
        self._save(network_requested=choices)
        return copy.deepcopy(choices)

    def project_created(self, project_id):
        project_id = _identifier(project_id, "project ID")
        if self.state not in ("started", "project_created") or \
                self._record.get("in_flight") not in (None, "project_create") or \
                (self.project_id and self.project_id != project_id):
            raise SetupProgressError("setup_progress_invalid: project checkpoint cannot change")
        self._save(state="project_created", project_id=project_id, in_flight=None)

    def identity_registered(self, actor_id, identity_mode=None, make_default=None):
        actor_id = _identifier(actor_id, "actor ID")
        if self.state not in ("project_created", "identity_registered") or \
                self._record.get("in_flight") not in (None, "identity_register") or \
                not actor_id.startswith(self.project_id + ".") or \
                (self.actor_id and self.actor_id != actor_id):
            raise SetupProgressError("setup_progress_invalid: identity checkpoint cannot change")
        _validate_actor(actor_id, self.project_id, self._record["scope"]["runtime"],
                        (self._record.get("network_requested") or {}).get("role"))
        selected = _registration_options(identity_mode, make_default)
        for key, value in selected.items():
            if key in self._record and self._record[key] != value:
                raise SetupProgressError("setup_progress_invalid: effective identity choices cannot change")
        self._save(state="identity_registered", actor_id=actor_id, in_flight=None, **selected)

    def complete(self):
        if self.state not in ("project_created", "identity_registered") or self._record.get("in_flight"):
            raise SetupProgressError("setup_progress_invalid: unfinished allocation cannot complete")
        self._save(state="completed")


def _network_choices(choices):
    if not isinstance(choices, dict) or set(choices) - NETWORK_FIELDS:
        raise SetupProgressError("setup_progress_invalid: unknown network choice fields")
    enums = {"role": ("keep", "director", "advisor", "worker"),
             "lead": ("keep", "current", "clear"),
             "identity_mode": ("auto", "reuse", "new", "temporary", "repair"),
             "relationship": (None, "none", "master", "peer", "advisor"),
             "principal": ("current", "other")}
    for key, values in enums.items():
        if key in choices and choices[key] not in values:
            raise SetupProgressError("setup_progress_invalid: invalid network %s" % key)
    for key in ("identity_actor", "bridge"):
        if choices.get(key) is not None:
            _identifier(choices[key], key)
    if "make_default" in choices and choices["make_default"] is not None \
            and not isinstance(choices["make_default"], bool):
        raise SetupProgressError("setup_progress_invalid: make_default must be boolean")
    _encoded(choices)
    return copy.deepcopy(choices)


def _validate_actor(actor_id, project_id, runtime, role=None):
    suffix = actor_id[len(project_id) + 1:].split(".")
    if not actor_id.startswith(project_id + ".") or len(suffix) not in (2, 3) \
            or suffix[0] not in ("director", "advisor", "worker") \
            or suffix[1] != runtime or (role and role != "keep" and suffix[0] != role):
        raise SetupProgressError("setup_progress_invalid: identity does not match workspace, runtime, and role")


def _registration_options(identity_mode, make_default):
    result = {}
    if identity_mode is not None:
        if identity_mode not in ("auto", "reuse", "new", "temporary", "repair"):
            raise SetupProgressError("setup_progress_invalid: invalid effective identity mode")
        result["identity_mode"] = identity_mode
    if make_default is not None:
        if not isinstance(make_default, bool):
            raise SetupProgressError("setup_progress_invalid: effective make_default must be boolean")
        result["make_default"] = make_default
    return result


def _validated_request(request):
    if not isinstance(request, dict) or set(request) - REQUEST_FIELDS:
        raise SetupProgressError("setup_progress_invalid: unknown setup request fields")
    enums = {"role": ("keep", "director", "advisor", "worker"),
             "lead": ("keep", "current", "clear"),
             "identity_mode": ("auto", "reuse", "new", "temporary", "repair"),
             "relationship": (None, "none", "master", "peer", "advisor"),
             "principal_side": ("current", "other"),
             "actor_type": ("agent", "human", "system")}
    for key, values in enums.items():
        if key in request and request[key] not in values:
            raise SetupProgressError("setup_progress_invalid: invalid requested %s" % key)
    for key in ("attach_project", "bridge", "identity_actor", "actor_id"):
        if request.get(key) is not None:
            _identifier(request[key], key)
    if request.get("create_project") is not None:
        name = request["create_project"]
        if not isinstance(name, str) or not name.strip() or len(name) > 512 \
                or any(ord(character) < 32 for character in name):
            raise SetupProgressError("setup_progress_invalid: invalid workspace name")
    for key in ("make_default", "here", "write_instructions", "manage_tools"):
        if key in request and request[key] is not None and not isinstance(request[key], bool):
            raise SetupProgressError("setup_progress_invalid: requested %s must be boolean" % key)
    if "skip_tools" in request:
        values = request["skip_tools"]
        if not isinstance(values, list) or len(values) > 32:
            raise SetupProgressError("setup_progress_invalid: invalid skipped tools")
        for value in values:
            _identifier(value, "skipped tool")
    _encoded(request)
    return copy.deepcopy(request)


def _validate(record, scope):
    fields = {"schema", "scope", "request_sha256", "operation_id", "state",
              "project_id", "actor_id", "in_flight", "network_requested",
              "identity_mode", "make_default", "request"}
    if set(record) - fields or record.get("schema") != 1 or record.get("scope") != scope \
            or record.get("state") not in STATES \
            or not re.fullmatch(r"[a-f0-9]{64}", str(record.get("request_sha256") or "")) \
            or not re.fullmatch(r"[a-f0-9]{32}", str(record.get("operation_id") or "")):
        raise SetupProgressError("setup_progress_invalid: record scope or schema mismatch")
    if "request" in record:
        request = _validated_request(record["request"])
        if _digest(request) != record["request_sha256"]:
            raise SetupProgressError("setup_progress_invalid: saved request fingerprint mismatch")
    state = record["state"]
    pending = record.get("in_flight")
    if (state == "started" and (record.get("project_id") is not None or record.get("actor_id") is not None)) \
            or (state == "project_created" and record.get("actor_id") is not None):
        raise SetupProgressError("setup_progress_invalid: checkpoint does not match state")
    if pending not in (None, "project_create", "identity_register") or \
            (pending == "project_create" and state != "started") or \
            (pending == "identity_register" and state != "project_created"):
        raise SetupProgressError("setup_progress_invalid: invalid allocation checkpoint")
    if state != "started":
        _identifier(record.get("project_id"), "project ID")
    if record.get("network_requested") is not None:
        _network_choices(record["network_requested"])
    _registration_options(record.get("identity_mode"), record.get("make_default"))
    if state == "identity_registered" or record.get("actor_id") is not None:
        _identifier(record.get("actor_id"), "actor ID")
        if not record.get("project_id") or not record["actor_id"].startswith(record["project_id"] + "."):
            raise SetupProgressError("setup_progress_invalid: identity belongs to another workspace")
        _validate_actor(record["actor_id"], record["project_id"], scope["runtime"],
                        (record.get("network_requested") or {}).get("role"))


def _scope_and_path(url, root_path, runtime, client_instance, storage_root):
    scope = {"server_url": canonical_server_url(url),
             "root_path": str(Path(root_path).expanduser().resolve()),
             "runtime": _identifier(runtime, "runtime"),
             "client_instance": _identifier(client_instance, "client installation")}
    directory = Path(storage_root or Path.home() / ".attacca" / "setup-progress").expanduser().absolute()
    _private_directory(directory)
    return scope, directory / (_digest(scope) + ".json")


@contextmanager
def _operation_lock(path):
    if fcntl is None and msvcrt is None:
        raise SetupProgressError("setup_progress_lock_unavailable: process locking is unavailable")
    lock_path = path.with_suffix(".lock")
    _check_components(lock_path)
    descriptor = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    locked = False
    try:
        _private_file(os.fstat(descriptor))
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # Windows byte-range lock, owned by this process/descriptor.
                if not os.fstat(descriptor).st_size:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            locked = True
        except (BlockingIOError, OSError):
            raise SetupProgressError("setup_in_progress: another apply owns this checkout operation") from None
        yield
    finally:
        if locked:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


@contextmanager
def operation(*, url, root_path, runtime, client_instance, request, storage_root=None):
    """Lock and begin/resume one exact confirmed setup; never store secrets.

    ``request`` accepts only the validated setup flags in REQUEST_FIELDS. The
    confirmed flags and digest are persisted, never credential fields. The
    caller must checkpoint allocation responses before
    performing subsequent operations, and call complete only at successful end.
    """
    request = _validated_request(request)
    fingerprint = _digest(request)
    scope, path = _scope_and_path(url, root_path, runtime, client_instance, storage_root)
    progress = None
    record = None
    try:
        with _operation_lock(path):
            record = _read(path)
            if record is not None:
                _validate(record, scope)
            resumed = bool(record and record["state"] != "completed")
            if resumed and record["request_sha256"] != fingerprint:
                if record["state"] == "started" and not record.get("in_flight"):
                    # No hosted allocation has begun: a corrected invalid flag
                    # is a fresh operation, not a partial-setup takeover.
                    resumed = False
                else:
                    raise SetupProgressError("setup_request_conflict: an unfinished setup has different confirmed choices; inspect its recorded progress before changing them")
            if resumed and record.get("in_flight"):
                raise SetupProgressError("setup_outcome_unknown: %s may already have succeeded; inspect hosted records before retrying; no allocation was repeated" % record["in_flight"])
            if not resumed:
                record = {"schema": 1, "scope": scope, "request_sha256": fingerprint,
                          "request": request,
                          "operation_id": uuid.uuid4().hex, "state": "started",
                          "project_id": None, "actor_id": None, "in_flight": None}
                _write(path, record)
            progress = SetupProgress(path, record, resumed)
            yield progress
    except SetupProgressError as error:
        raise error._with_progress(path, progress.record if progress else record) from None
    finally:
        if progress is not None:
            progress._active = False


def inspect_pending(*, url, root_path, runtime, client_instance, storage_root=None):
    """Read exact-scope unfinished progress; never infer another operation.

    An old schema-v1 record without saved request flags remains readable. Its
    absent choices must not be guessed by callers. Inspection never clears an
    ambiguous allocation or grants hosted authority.
    """
    scope, path = _scope_and_path(url, root_path, runtime, client_instance, storage_root)
    record = None
    try:
        with _operation_lock(path):
            record = _read(path)
            if record is None:
                return None
            _validate(record, scope)
            return copy.deepcopy(record) if record["state"] != "completed" else None
    except SetupProgressError as error:
        raise error._with_progress(path, record) from None


def recover(*, url, root_path, runtime, client_instance, project_id,
            actor_id=None, storage_root=None):
    """Checkpoint a formerly ambiguous allocation after hosted verification.

    The caller MUST verify the exact hosted allocation belongs to this original
    operation and retain the user's confirmed choices. This low-level helper
    does no network access, grants no authority, and cannot erase ambiguity or
    mark an operation complete merely by receiving arbitrary local state.
    """
    scope, path = _scope_and_path(url, root_path, runtime, client_instance, storage_root)
    record = None
    try:
        with _operation_lock(path):
            record = _read(path)
            if record is None:
                raise SetupProgressError("setup_progress_missing: no allocation to recover")
            _validate(record, scope)
            action = record.get("in_flight")
            progress = SetupProgress(path, record, True)
            try:
                if action == "project_create" and actor_id is None:
                    progress.project_created(project_id)
                elif action == "identity_register" and project_id == progress.project_id and actor_id:
                    progress.identity_registered(actor_id)
                else:
                    raise SetupProgressError("setup_progress_invalid: recovery does not match ambiguous allocation")
                return progress.record
            finally:
                progress._active = False
    except SetupProgressError as error:
        raise error._with_progress(path, record) from None
