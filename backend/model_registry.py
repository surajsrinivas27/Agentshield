"""
Model Registry — AgentShield

Imports all SQLAlchemy ORM model modules so their table metadata is
registered on the shared backend.common.database.Base before init_db()
is called.

Usage in application entry point (e.g. main.py):
-------------------------------------------------
    import backend.model_registry          # registers all ORM tables
    from backend.common.database import init_db
    init_db()                              # creates tables if they do not exist

Design rules
------------
- This module only imports; it never instantiates models or calls init_db().
- backend/__init__.py remains empty; model loading is explicit and controlled.
- Import order matters for readability but not for correctness — SQLAlchemy
  resolves string-based ForeignKey references at metadata.create_all() time,
  not at Python import time.
- Tests that need isolated databases must import this module (or the individual
  model modules) before creating their test engines and calling create_all().
"""

# Step 1: User, RevokedToken and other authorization tables.
#         No FK dependency on agent models.
import backend.authorization.models  # noqa: F401  — registers User

# Step 2: Task and ProvenanceRecord.
#         Task.principal_id → "users.id" (string FK, resolved at DDL time).
#         ProvenanceRecord.task_id → "tasks.task_id" (string FK, same).
import backend.agent.models  # noqa: F401  — registers Task, ProvenanceRecord
