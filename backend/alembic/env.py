from alembic import context

from app.config import settings
from app.db import Base, make_engine
from app import models  # noqa: F401  (registers tables)

config = context.config


def render_item(type_, obj, autogen_context):
    # Keep migrations free of app imports: UTCDateTime is a plain timezone-aware DateTime in the DB.
    if type_ == "type" and type(obj).__name__ == "UTCDateTime":
        return "sa.DateTime(timezone=True)"
    return False


def run_migrations_online() -> None:
    url = config.attributes.get("url") or settings.database_url
    connectable = make_engine(url)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, render_item=render_item,
                          render_as_batch=url.startswith("sqlite"), compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
