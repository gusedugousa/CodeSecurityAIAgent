# Migrations

The MVP creates tables via `SQLAlchemy`'s `Base.metadata.create_all()` at startup
(`app/persistence/db.py::init_db`) rather than versioned migrations — acceptable for a
single-schema MVP with no production data to migrate.

Future work: introduce Alembic here once the schema needs to evolve against a populated
production database without data loss (see `docs/extension_points.md`).
