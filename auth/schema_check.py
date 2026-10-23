from typing import List, Optional, Sequence, Tuple, Union

from sqlalchemy import Table, inspect
from sqlalchemy.engine import Connection, Engine

Bind = Union[Engine, Connection]


class SchemaMismatchError(RuntimeError):
    def __init__(
        self, missing_tables: Sequence[str], missing_columns: Sequence[str]
    ) -> None:
        self.missing_tables = list(missing_tables)
        self.missing_columns = list(missing_columns)
        parts = []
        if self.missing_tables:
            parts.append("missing tables: " + ", ".join(self.missing_tables))
        if self.missing_columns:
            parts.append("missing columns: " + ", ".join(self.missing_columns))
        super().__init__(
            "the live database is behind the installed auth models ("
            + "; ".join(parts)
            + "). The auth changelog lists the DDL each release needs."
        )


def _qualified(table: Table) -> str:
    return f"{table.schema}.{table.name}" if table.schema else table.name


def find_schema_drift(bind: Bind) -> Tuple[List[str], List[str]]:
    import auth.audit  # noqa: F401
    from auth.models.sql import Base

    inspector = inspect(bind)
    missing_tables: List[str] = []
    missing_columns: List[str] = []
    for table in sorted(Base.metadata.tables.values(), key=_qualified):
        if not inspector.has_table(table.name, schema=table.schema):
            missing_tables.append(_qualified(table))
            continue
        live = {
            column["name"]
            for column in inspector.get_columns(table.name, schema=table.schema)
        }
        missing_columns.extend(
            f"{_qualified(table)}.{column.name}"
            for column in table.columns
            if column.name not in live
        )
    return missing_tables, missing_columns


def check_schema(bind: Optional[Bind] = None) -> None:
    if bind is None:
        from auth.database import engine

        bind = engine
    missing_tables, missing_columns = find_schema_drift(bind)
    if missing_tables or missing_columns:
        raise SchemaMismatchError(missing_tables, missing_columns)
