"""
Tests for Stage 1 ORM models:
  backend/authorization/models.py  → User
  backend/agent/models.py          → Task, ProvenanceRecord
  backend/model_registry.py        → model registration

Verifies:
- Table names and column presence on the shared Base metadata.
- String(36) UUID primary keys on all three models.
- JSON columns with callable (not shared-mutable) defaults.
- tasks.principal_id → users.id foreign key enforced by SQLite.
- provenance_records.task_id → tasks.task_id foreign key enforced by SQLite.
- No duplicate Base or engine — only backend.common.database.Base is used.
- Correct model registration through model_registry.
- All tests use temporary in-memory or file-based databases; no production DB
  files are created.
"""

import uuid
import tempfile
import os
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import sessionmaker

# -- Trigger model registration on the shared Base --
import backend.model_registry  # noqa: F401

from backend.common.database import Base, UTCDateTime, engine as production_engine
from backend.authorization.models import (
    User,
    ROLE_EMPLOYEE,
    ROLE_MANAGER,
    ROLE_ADMINISTRATOR,
    SUPPORTED_ROLES,
)
from backend.agent.models import (
    Task,
    ProvenanceRecord,
    TASK_STATUS_ACTIVE,
    TASK_STATUS_COMPLETED,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    ORIGIN_USER_PROVIDED,
    ORIGIN_EXTERNAL,
    TAINT_UNTRUSTED_DATA,
    TAINT_UNTRUSTED_INSTRUCTIONS,
    VALID_TAINT_LABELS,
    _empty_list,
)


def _sample_expiry() -> datetime:
    """Return a valid UTC expiry 1 hour in the future."""
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _sample_manifest(task_id: str = "task-default", user_id: str = "user-default") -> dict:
    """Generate a valid signed capability manifest dict for task fixtures."""
    return {
        "task_id": task_id,
        "user_id": user_id,
        "task_type": "default_task",
        "allowed_operations": ["read"],
        "allowed_resource_ids": ["RES_001"],
        "permitted_recipients": ["user@example.com"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "manifest_signature": "0123456789abcdef" * 4,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mem_engine():
    """
    In-memory SQLite engine with all tables created from the shared Base.
    Scoped to the module so the schema is built once and shared across tests.
    """
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        future=True,
    )
    # Enable foreign keys for the in-memory engine
    from sqlalchemy import event

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _rec):
        dbapi_conn.execute("PRAGMA foreign_keys = ON;")

    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def mem_session_factory(mem_engine):
    return sessionmaker(
        autocommit=False, autoflush=False, bind=mem_engine, future=True
    )


@pytest.fixture
def db(mem_session_factory):
    """Provides a session and rolls back after each test for isolation."""
    session = mem_session_factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="module")
def file_engine():
    """
    File-based temporary SQLite engine used for FK enforcement tests that
    need separate connections.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name

    from sqlalchemy import event

    eng = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
        future=True,
    )

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _rec):
        dbapi_conn.execute("PRAGMA foreign_keys = ON;")

    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()

    for ext in ["", "-wal", "-shm"]:
        p = path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


@pytest.fixture
def file_db(file_engine):
    sf = sessionmaker(
        autocommit=False, autoflush=False, bind=file_engine, future=True
    )
    session = sf()
    yield session
    session.rollback()
    session.close()


# ---------------------------------------------------------------------------
# 1. Table registration on shared Base
# ---------------------------------------------------------------------------

class TestModelRegistration:

    def test_users_table_in_base_metadata(self):
        """User registers 'users' on the shared Base metadata."""
        assert "users" in Base.metadata.tables

    def test_tasks_table_in_base_metadata(self):
        """Task registers 'tasks' on the shared Base metadata."""
        assert "tasks" in Base.metadata.tables

    def test_provenance_records_table_in_base_metadata(self):
        """ProvenanceRecord registers 'provenance_records' on the shared Base metadata."""
        assert "provenance_records" in Base.metadata.tables

    def test_model_registry_idempotent(self):
        """Re-importing model_registry does not raise or duplicate tables."""
        import importlib
        import backend.model_registry as reg
        importlib.reload(reg)
        assert "users" in Base.metadata.tables
        assert "tasks" in Base.metadata.tables
        assert "provenance_records" in Base.metadata.tables

    def test_no_duplicate_base(self):
        """All three models use the identical Base object — not separate bases."""
        assert User.__table__.metadata is Base.metadata
        assert Task.__table__.metadata is Base.metadata
        assert ProvenanceRecord.__table__.metadata is Base.metadata

    def test_no_duplicate_engine(self):
        """
        The production engine imported from backend.common.database is the
        single shared engine.  Model files must not define their own engines.
        """
        import backend.authorization.models as auth_models
        import backend.agent.models as agent_models
        # Neither module should expose an `engine` attribute of its own
        assert not hasattr(auth_models, "engine"), (
            "backend.authorization.models must not define its own engine"
        )
        assert not hasattr(agent_models, "engine"), (
            "backend.agent.models must not define its own engine"
        )
        # Production engine is the one from common
        assert production_engine is not None


# ---------------------------------------------------------------------------
# 2. Column presence and types
# ---------------------------------------------------------------------------

class TestUserColumns:

    def test_user_table_name(self):
        assert User.__tablename__ == "users"

    def test_user_primary_key_column(self):
        col = User.__table__.c["id"]
        assert col.primary_key is True
        assert str(col.type) == "VARCHAR(36)"

    def test_user_required_columns_exist(self, mem_engine):
        insp = inspect(mem_engine)
        cols = {c["name"] for c in insp.get_columns("users")}
        required = {
            "id", "username", "password_hash", "role",
            "department", "is_active", "token_valid_after", "created_at",
        }
        assert required <= cols, f"Missing columns: {required - cols}"

    def test_user_username_unique(self):
        col = User.__table__.c["username"]
        # unique constraint may be listed on the column or as a separate UniqueConstraint
        unique_via_col = col.unique
        unique_via_constraint = any(
            hasattr(uc, "columns") and "username" in [c.name for c in uc.columns]
            for uc in User.__table__.constraints
        )
        assert unique_via_col or unique_via_constraint, (
            "username column must have a UNIQUE constraint"
        )

    def test_user_password_hash_not_plaintext_field(self):
        """Column is named password_hash, not password, to enforce hashing discipline."""
        assert "password_hash" in User.__table__.c
        assert "password" not in User.__table__.c

    def test_user_role_constants(self):
        assert ROLE_EMPLOYEE == "Employee"
        assert ROLE_MANAGER == "Manager"
        assert ROLE_ADMINISTRATOR == "Administrator"
        assert SUPPORTED_ROLES == {"Employee", "Manager", "Administrator"}


class TestTaskColumns:

    def test_task_table_name(self):
        assert Task.__tablename__ == "tasks"

    def test_task_primary_key_column(self):
        col = Task.__table__.c["task_id"]
        assert col.primary_key is True
        assert str(col.type) == "VARCHAR(36)"

    def test_task_principal_id_column_exists(self):
        assert "principal_id" in Task.__table__.c

    def test_task_has_no_user_id_column(self):
        """Column must be named principal_id, never user_id."""
        assert "user_id" not in Task.__table__.c

    def test_task_required_columns_exist(self, mem_engine):
        insp = inspect(mem_engine)
        cols = {c["name"] for c in insp.get_columns("tasks")}
        required = {
            "task_id", "principal_id", "task_type",
            "resource_ids", "allowed_operations", "permitted_recipients",
            "created_at", "expires_at", "status", "capability_manifest",
        }
        assert required <= cols, f"Missing columns: {required - cols}"

    def test_task_expires_at_non_nullable(self):
        """expires_at must be non-nullable at the schema level."""
        col = Task.__table__.c["expires_at"]
        assert col.nullable is False

    def test_task_capability_manifest_non_nullable(self):
        """capability_manifest must be non-nullable at the schema level."""
        col = Task.__table__.c["capability_manifest"]
        assert col.nullable is False

    def test_task_status_default(self):
        tid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        t = Task(
            task_id=tid,
            principal_id=pid,
            task_type="summarize_email",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(tid, pid),
        )
        # SQLAlchemy ColumnDefault is not applied until flush, but the
        # Python-level default is accessible via the Column default callable
        default = Task.__table__.c["status"].default.arg
        assert default == TASK_STATUS_ACTIVE

    def test_task_status_constants(self):
        assert TASK_STATUS_ACTIVE == "ACTIVE"
        assert TASK_STATUS_COMPLETED == "COMPLETED"

    def test_task_null_expires_at_raises_integrity_error(self, file_db):
        """Attempting to commit a Task with expires_at=None must raise IntegrityError."""
        uid = str(uuid.uuid4())
        user = User(
            id=uid,
            username=f"null_exp_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user)
        file_db.commit()

        tid = str(uuid.uuid4())
        task = Task(
            task_id=tid,
            principal_id=uid,
            task_type="null_expiry_test",
            expires_at=None,  # Invalid: non-nullable
            capability_manifest=_sample_manifest(tid, uid),
        )
        file_db.add(task)
        with pytest.raises(IntegrityError):
            file_db.commit()
        file_db.rollback()

    def test_task_null_capability_manifest_raises_integrity_error(self, file_db):
        """Attempting to commit a Task with capability_manifest=None must raise IntegrityError."""
        uid = str(uuid.uuid4())
        user = User(
            id=uid,
            username=f"null_man_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user)
        file_db.commit()

        tid = str(uuid.uuid4())
        task = Task(
            task_id=tid,
            principal_id=uid,
            task_type="null_manifest_test",
            expires_at=_sample_expiry(),
            capability_manifest=None,  # Invalid: non-nullable
        )
        file_db.add(task)
        with pytest.raises(IntegrityError):
            file_db.commit()
        file_db.rollback()


class TestProvenanceRecordColumns:

    def test_provenance_table_name(self):
        assert ProvenanceRecord.__tablename__ == "provenance_records"

    def test_provenance_primary_key_column(self):
        col = ProvenanceRecord.__table__.c["source_id"]
        assert col.primary_key is True
        assert str(col.type) == "VARCHAR(36)"

    def test_provenance_task_id_column_exists(self):
        assert "task_id" in ProvenanceRecord.__table__.c

    def test_provenance_required_columns_exist(self, mem_engine):
        insp = inspect(mem_engine)
        cols = {c["name"] for c in insp.get_columns("provenance_records")}
        required = {
            "source_id", "task_id", "origin", "source_type",
            "source_origin", "trust_level", "content_hash",
            "taint_labels", "created_at",
        }
        assert required <= cols, f"Missing columns: {required - cols}"

    def test_provenance_trust_constants(self):
        assert TRUST_TRUSTED == "TRUSTED"
        assert TRUST_UNTRUSTED == "UNTRUSTED"
        assert ORIGIN_USER_PROVIDED == "USER_PROVIDED"
        assert ORIGIN_EXTERNAL == "EXTERNAL"


# ---------------------------------------------------------------------------
# 3. JSON columns and callable defaults
# ---------------------------------------------------------------------------

class TestJsonColumnsAndDefaults:

    def test_task_json_columns_have_callable_defaults(self):
        """
        JSON list columns must use a callable default (_empty_list), not a
        shared mutable literal [].  Sharing a mutable default across rows
        causes data corruption.
        """
        for col_name in ("resource_ids", "allowed_operations", "permitted_recipients"):
            col = Task.__table__.c[col_name]
            assert callable(col.default.arg), (
                f"Task.{col_name} default must be a callable, not a literal"
            )

    def test_provenance_taint_labels_callable_default(self):
        col = ProvenanceRecord.__table__.c["taint_labels"]
        assert callable(col.default.arg), (
            "ProvenanceRecord.taint_labels default must be a callable"
        )

    def test_empty_list_callable_returns_new_list_each_call(self):
        """_empty_list() must return a fresh list every time to prevent shared state."""
        list1 = _empty_list()
        list2 = _empty_list()
        assert list1 == []
        assert list1 is not list2

    def test_task_json_roundtrip(self, db):
        """JSON lists are stored and retrieved correctly."""
        task_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"jsontest_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        db.add(user)
        db.flush()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="json_roundtrip",
            resource_ids=["RES_A", "RES_B"],
            allowed_operations=["read", "summarize"],
            permitted_recipients=["alice@example.com"],
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        db.add(task)
        db.flush()

        fetched = db.get(Task, task_id)
        assert fetched.resource_ids == ["RES_A", "RES_B"]
        assert fetched.allowed_operations == ["read", "summarize"]
        assert fetched.permitted_recipients == ["alice@example.com"]

    def test_provenance_taint_labels_roundtrip(self, db):
        """taint_labels JSON list is stored and retrieved correctly with canonical labels."""
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        prov_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"tainttest_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        db.add(user)
        db.flush()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="taint_test",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        db.add(task)
        db.flush()

        prov = ProvenanceRecord(
            source_id=prov_id,
            task_id=task_id,
            origin="EMAIL_001",
            source_type="email",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="a" * 64,
            taint_labels=[TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS],
        )
        db.add(prov)
        db.flush()

        fetched = db.get(ProvenanceRecord, prov_id)
        assert fetched.taint_labels == [TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS]


# ---------------------------------------------------------------------------
# 4. CRUD roundtrips
# ---------------------------------------------------------------------------

class TestUserCRUD:

    def test_create_and_retrieve_user(self, db):
        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            username=f"alice_{user_id[:8]}",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$HASH",
            role=ROLE_EMPLOYEE,
            department="Engineering",
        )
        db.add(user)
        db.flush()

        fetched = db.get(User, user_id)
        assert fetched is not None
        assert fetched.username.startswith("alice_")
        assert fetched.role == ROLE_EMPLOYEE
        assert fetched.department == "Engineering"
        assert fetched.is_active is True

    def test_user_created_at_is_utc_aware(self, db):
        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            username=f"utctest_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_MANAGER,
        )
        db.add(user)
        db.commit()
        db.expunge_all()
        fetched = db.get(User, user_id)
        assert fetched.created_at is not None
        # created_at must be timezone-aware and UTC
        assert fetched.created_at.tzinfo is not None
        assert fetched.created_at.tzinfo == timezone.utc

    def test_user_username_uniqueness_enforced(self, file_db):
        """SQLite enforces the UNIQUE constraint on username."""
        uid1 = str(uuid.uuid4())
        uid2 = str(uuid.uuid4())
        username = f"dupuser_{uid1[:8]}"

        user1 = User(
            id=uid1,
            username=username,
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user1)
        file_db.commit()

        user2 = User(
            id=uid2,
            username=username,  # intentional duplicate
            password_hash="$argon2id$placeholder",
            role=ROLE_MANAGER,
        )
        file_db.add(user2)
        with pytest.raises(IntegrityError):
            file_db.commit()
        file_db.rollback()


# ---------------------------------------------------------------------------
# 5. Foreign key enforcement — tasks.principal_id → users.id
# ---------------------------------------------------------------------------

class TestUserToTaskForeignKey:

    def test_task_requires_valid_principal_id(self, file_db):
        """
        Inserting a Task with a principal_id that does not exist in users
        must raise IntegrityError.
        """
        tid = str(uuid.uuid4())
        pid = str(uuid.uuid4())
        orphan_task = Task(
            task_id=tid,
            principal_id=pid,  # no matching user
            task_type="orphan",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(tid, pid),
        )
        file_db.add(orphan_task)
        with pytest.raises(IntegrityError):
            file_db.commit()
        file_db.rollback()

    def test_task_with_valid_principal_id_persists(self, file_db):
        """A Task referencing a real user is accepted."""
        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            username=f"valid_principal_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user)
        file_db.commit()

        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="summarize_email",
            resource_ids=["EMAIL_001"],
            allowed_operations=["read"],
            permitted_recipients=[],
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        file_db.add(task)
        file_db.commit()

        fetched = file_db.get(Task, task_id)
        assert fetched is not None
        assert fetched.principal_id == user_id


# ---------------------------------------------------------------------------
# 6. Foreign key enforcement — provenance_records.task_id → tasks.task_id
# ---------------------------------------------------------------------------

class TestTaskToProvenanceForeignKey:

    def test_provenance_requires_valid_task_id(self, file_db):
        """
        Inserting a ProvenanceRecord with a task_id that does not exist
        in tasks must raise IntegrityError.
        """
        orphan_prov = ProvenanceRecord(
            source_id=str(uuid.uuid4()),
            task_id=str(uuid.uuid4()),  # no matching task
            origin="EMAIL_999",
            source_type="email",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="b" * 64,
        )
        file_db.add(orphan_prov)
        with pytest.raises(IntegrityError):
            file_db.commit()
        file_db.rollback()

    def test_provenance_with_valid_task_id_persists(self, file_db):
        """A ProvenanceRecord referencing a real task is accepted."""
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        prov_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"prov_owner_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user)
        file_db.commit()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="read_doc",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        file_db.add(task)
        file_db.commit()

        prov = ProvenanceRecord(
            source_id=prov_id,
            task_id=task_id,
            origin="DOC_42",
            source_type="document",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="c" * 64,
        )
        file_db.add(prov)
        file_db.commit()

        fetched = file_db.get(ProvenanceRecord, prov_id)
        assert fetched is not None
        assert fetched.task_id == task_id
        assert fetched.origin == "DOC_42"

    def test_task_to_provenance_relationship_accessible(self, db):
        """The SQLAlchemy relationship Task.provenance_records is accessible."""
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"rel_test_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_MANAGER,
        )
        db.add(user)
        db.flush()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="rel_test",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        db.add(task)
        db.flush()

        prov = ProvenanceRecord(
            source_id=str(uuid.uuid4()),
            task_id=task_id,
            origin="EMAIL_REL",
            source_type="email",
            source_origin=ORIGIN_USER_PROVIDED,
            trust_level=TRUST_TRUSTED,
            content_hash="d" * 64,
        )
        db.add(prov)
        db.flush()

        fetched_task = db.get(Task, task_id)
        assert len(fetched_task.provenance_records) == 1
        assert fetched_task.provenance_records[0].origin == "EMAIL_REL"


# ---------------------------------------------------------------------------
# 7. Capability manifest JSON storage
# ---------------------------------------------------------------------------

class TestCapabilityManifestStorage:

    def test_capability_manifest_stored_and_retrieved(self, db):
        """capability_manifest stores the full signed manifest dict."""
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"mtest_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_ADMINISTRATOR,
        )
        db.add(user)
        db.flush()

        manifest = {
            "task_id": task_id,
            "user_id": user_id,
            "task_type": "forward_email",
            "allowed_operations": ["forward"],
            "allowed_resource_ids": ["EMAIL_001"],
            "permitted_recipients": ["bob@example.com"],
            "expires_at": "2026-11-14T00:00:00+00:00",
            "manifest_signature": "aabbcc1122334455" * 4,
        }
        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="forward_email",
            expires_at=_sample_expiry(),
            capability_manifest=manifest,
        )
        db.add(task)
        db.flush()

        fetched = db.get(Task, task_id)
        assert fetched.capability_manifest is not None
        assert fetched.capability_manifest["manifest_signature"] == manifest["manifest_signature"]
        assert fetched.capability_manifest["task_id"] == task_id


# ---------------------------------------------------------------------------
# 8. Timezone handling and UTCDateTime round-trips
# ---------------------------------------------------------------------------

class TestDateTimeTimezoneHandling:

    def test_all_datetime_columns_remain_utc_aware_after_commit_and_expunge(self, file_db):
        """
        Verify that commit, expunge and reload retains timezone-aware UTC
        datetimes across User, Task and ProvenanceRecord in SQLite.
        """
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        prov_id = str(uuid.uuid4())

        now_utc = datetime.now(timezone.utc)
        token_after = now_utc - timedelta(hours=2)
        task_expiry = now_utc + timedelta(hours=4)

        user = User(
            id=user_id,
            username=f"tztest_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_MANAGER,
            created_at=now_utc,
            token_valid_after=token_after,
        )
        file_db.add(user)
        file_db.commit()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="tz_test",
            created_at=now_utc,
            expires_at=task_expiry,
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        file_db.add(task)
        file_db.commit()

        prov = ProvenanceRecord(
            source_id=prov_id,
            task_id=task_id,
            origin="EMAIL_TZ",
            source_type="email",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="e" * 64,
            taint_labels=[TAINT_UNTRUSTED_DATA],
            created_at=now_utc,
        )
        file_db.add(prov)
        file_db.commit()

        # Detach/evict all instances from session to force reload from SQLite
        file_db.expunge_all()

        reloaded_user = file_db.get(User, user_id)
        assert reloaded_user.created_at.tzinfo is not None
        assert reloaded_user.created_at.tzinfo == timezone.utc
        assert reloaded_user.token_valid_after.tzinfo is not None
        assert reloaded_user.token_valid_after.tzinfo == timezone.utc

        reloaded_task = file_db.get(Task, task_id)
        assert reloaded_task.created_at.tzinfo is not None
        assert reloaded_task.created_at.tzinfo == timezone.utc
        assert reloaded_task.expires_at.tzinfo is not None
        assert reloaded_task.expires_at.tzinfo == timezone.utc

        reloaded_prov = file_db.get(ProvenanceRecord, prov_id)
        assert reloaded_prov.created_at.tzinfo is not None
        assert reloaded_prov.created_at.tzinfo == timezone.utc

    def test_naive_datetime_rejected_by_utc_datetime(self, file_db):
        """UTCDateTime must reject naive datetime inputs on flush/commit."""
        uid = str(uuid.uuid4())
        # Naive datetime: no tzinfo
        naive_dt = datetime.now()

        user = User(
            id=uid,
            username=f"naive_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
            created_at=naive_dt,
        )
        file_db.add(user)
        with pytest.raises(StatementError) as exc_info:
            file_db.commit()
        assert "UTCDateTime requires a timezone-aware datetime object" in str(exc_info.value)
        file_db.rollback()

    def test_non_utc_timezone_normalized_to_utc(self, file_db):
        """Timezone-aware datetime with non-UTC offset is normalized to UTC on store/reload."""
        uid = str(uuid.uuid4())
        # Offset +05:30 (e.g. IST)
        offset_tz = timezone(timedelta(hours=5, minutes=30))
        ist_dt = datetime(2026, 11, 14, 12, 0, 0, tzinfo=offset_tz)

        user = User(
            id=uid,
            username=f"offset_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
            created_at=ist_dt,
        )
        file_db.add(user)
        file_db.commit()
        file_db.expunge_all()

        reloaded = file_db.get(User, uid)
        assert reloaded.created_at.tzinfo == timezone.utc
        # Must represent identical instant in time
        assert reloaded.created_at.timestamp() == ist_dt.timestamp()


# ---------------------------------------------------------------------------
# 9. Provenance retention and cascade safety
# ---------------------------------------------------------------------------

class TestProvenanceRetention:

    def test_task_provenance_relationship_cascade_has_no_delete(self):
        """Task.provenance_records relationship must not cascade delete or delete-orphan."""
        cascade_options = str(Task.provenance_records.property.cascade)
        assert "delete" not in cascade_options.split(",")
        assert "delete-orphan" not in cascade_options

    def test_provenance_task_id_foreign_key_ondelete_is_restrict(self):
        """provenance_records.task_id FK constraint must specify ondelete='RESTRICT'."""
        fks = list(ProvenanceRecord.__table__.c["task_id"].foreign_keys)
        assert len(fks) == 1
        fk = fks[0]
        assert fk.ondelete is not None
        assert fk.ondelete.upper() == "RESTRICT"

    def test_deleting_task_blocked_when_provenance_records_exist_orm(self, file_db):
        """
        Attempting to delete a Task that owns ProvenanceRecords via the ORM
        must fail with IntegrityError, preventing silent deletion of provenance history.
        """
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        prov_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"retention_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_MANAGER,
        )
        file_db.add(user)
        file_db.commit()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="retention_test",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        file_db.add(task)
        file_db.commit()

        prov = ProvenanceRecord(
            source_id=prov_id,
            task_id=task_id,
            origin="AUDIT_001",
            source_type="email",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="f" * 64,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        file_db.add(prov)
        file_db.commit()

        # Attempt to delete the parent Task
        task_to_delete = file_db.get(Task, task_id)
        file_db.delete(task_to_delete)

        with pytest.raises(IntegrityError):
            file_db.commit()
        file_db.rollback()

        # Verify provenance record is completely preserved and intact
        preserved = file_db.get(ProvenanceRecord, prov_id)
        assert preserved is not None
        assert preserved.origin == "AUDIT_001"
        assert preserved.task_id == task_id

    def test_raw_sql_delete_task_blocked_by_foreign_key_restrict(self, file_db):
        """
        Direct SQL DELETE on tasks when provenance records exist must be blocked
        by SQLite's foreign key ON RESTRICT enforcement.
        """
        user_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        prov_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            username=f"sql_ret_{user_id[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user)
        file_db.commit()

        task = Task(
            task_id=task_id,
            principal_id=user_id,
            task_type="sql_ret_test",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(task_id, user_id),
        )
        file_db.add(task)
        file_db.commit()

        prov = ProvenanceRecord(
            source_id=prov_id,
            task_id=task_id,
            origin="AUDIT_SQL",
            source_type="document",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="1" * 64,
            taint_labels=[TAINT_UNTRUSTED_INSTRUCTIONS],
        )
        file_db.add(prov)
        file_db.commit()

        with pytest.raises(IntegrityError):
            file_db.execute(text("DELETE FROM tasks WHERE task_id = :tid"), {"tid": task_id})
            file_db.commit()
        file_db.rollback()

        preserved = file_db.get(ProvenanceRecord, prov_id)
        assert preserved is not None
        assert preserved.source_id == prov_id


# ---------------------------------------------------------------------------
# 10. Canonical taint label validation and consistency
# ---------------------------------------------------------------------------

class TestCanonicalTaintLabels:

    def test_canonical_taint_label_constants(self):
        """Verify canonical taint label constant values and collection."""
        assert TAINT_UNTRUSTED_DATA == "UNTRUSTED_DATA"
        assert TAINT_UNTRUSTED_INSTRUCTIONS == "UNTRUSTED_INSTRUCTIONS"
        assert VALID_TAINT_LABELS == {"UNTRUSTED_DATA", "UNTRUSTED_INSTRUCTIONS"}

    def test_provenance_valid_taint_labels_persisted(self, file_db):
        """ProvenanceRecord accepts all valid canonical taint labels."""
        uid = str(uuid.uuid4())
        tid = str(uuid.uuid4())
        pid1 = str(uuid.uuid4())
        pid2 = str(uuid.uuid4())
        pid3 = str(uuid.uuid4())

        user = User(
            id=uid,
            username=f"prov_labels_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
        )
        file_db.add(user)
        file_db.commit()

        task = Task(
            task_id=tid,
            principal_id=uid,
            task_type="valid_labels_test",
            expires_at=_sample_expiry(),
            capability_manifest=_sample_manifest(tid, uid),
        )
        file_db.add(task)
        file_db.commit()

        # 1. UNTRUSTED_DATA alone
        p1 = ProvenanceRecord(
            source_id=pid1,
            task_id=tid,
            origin="SRC_1",
            source_type="email",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="2" * 64,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        # 2. UNTRUSTED_INSTRUCTIONS alone
        p2 = ProvenanceRecord(
            source_id=pid2,
            task_id=tid,
            origin="SRC_2",
            source_type="document",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="3" * 64,
            taint_labels=[TAINT_UNTRUSTED_INSTRUCTIONS],
        )
        # 3. Both canonical labels
        p3 = ProvenanceRecord(
            source_id=pid3,
            task_id=tid,
            origin="SRC_3",
            source_type="api_response",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="4" * 64,
            taint_labels=[TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS],
        )
        file_db.add_all([p1, p2, p3])
        file_db.commit()
        file_db.expunge_all()

        assert file_db.get(ProvenanceRecord, pid1).taint_labels == [TAINT_UNTRUSTED_DATA]
        assert file_db.get(ProvenanceRecord, pid2).taint_labels == [TAINT_UNTRUSTED_INSTRUCTIONS]
        assert file_db.get(ProvenanceRecord, pid3).taint_labels == [
            TAINT_UNTRUSTED_DATA,
            TAINT_UNTRUSTED_INSTRUCTIONS,
        ]

    def test_provenance_invalid_taint_label_rejected_at_assignment(self):
        """Unrecognized or unmapped runtime categories must be rejected with ValueError."""
        invalid_labels = ["EXTERNAL_INSTRUCTION", "UNTRUSTED_SOURCE", "RANDOM_LABEL"]
        for invalid in invalid_labels:
            with pytest.raises(ValueError) as exc_info:
                ProvenanceRecord(
                    source_id=str(uuid.uuid4()),
                    task_id=str(uuid.uuid4()),
                    origin="SRC_X",
                    source_type="email",
                    source_origin=ORIGIN_EXTERNAL,
                    content_hash="5" * 64,
                    taint_labels=[invalid],
                )
            assert f"Invalid taint label '{invalid}'" in str(exc_info.value)
            assert "VALID_TAINT_LABELS" in str(exc_info.value)

    def test_provenance_non_collection_taint_labels_rejected(self):
        """taint_labels must be a list/collection of strings."""
        with pytest.raises(TypeError):
            ProvenanceRecord(
                source_id=str(uuid.uuid4()),
                task_id=str(uuid.uuid4()),
                origin="SRC_Y",
                source_type="email",
                source_origin=ORIGIN_EXTERNAL,
                content_hash="6" * 64,
                taint_labels="NOT_A_LIST",  # type: ignore[arg-type]
            )

        with pytest.raises(TypeError):
            ProvenanceRecord(
                source_id=str(uuid.uuid4()),
                task_id=str(uuid.uuid4()),
                origin="SRC_Z",
                source_type="email",
                source_origin=ORIGIN_EXTERNAL,
                content_hash="7" * 64,
                taint_labels=[123],  # type: ignore[list-item]
            )
