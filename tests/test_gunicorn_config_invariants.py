"""The deployment's worker model, asserted rather than commented.

gunicorn resolves `worker_class = "sync"` to gthread whenever `threads > 1`,
silently -- `Config.worker_class` does it, not the config file. So a future
change that raises threads for any reason reinstates the thread pool while
gunicorn_config.py still reads "sync", and the only evidence is one line in a
startup log nobody diffs.

That mattered here: the thread pool correlated with 9 premature connection
closes in 81 minutes against zero in 1,766,168 requests under sync (#21). The
constraint was written as a comment when it was discovered, which protects
nothing once the comment is out of view.

gunicorn is not a test dependency, so this reads the config as source rather
than importing it -- the invariant is about what the file says, which is what a
reviewer sees and what gunicorn will later read.
"""

import ast
import pathlib

import pytest

CONFIG = pathlib.Path(__file__).resolve().parent.parent / "gunicorn_config.py"


def _assignments():
    tree = ast.parse(CONFIG.read_text())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                try:
                    out[target.id] = ast.literal_eval(node.value)
                except ValueError:
                    pass
    return out


@pytest.fixture(scope="module")
def config():
    values = _assignments()
    assert {"workers", "worker_class", "threads"} <= set(values), (
        f"the parser found {sorted(values)} and is missing one of workers, "
        "worker_class or threads -- it is not reading the file it thinks it "
        "is, and would pass every assertion below by finding nothing"
    )
    for name, kind in (("workers", int), ("threads", int), ("worker_class", str)):
        assert isinstance(values[name], kind), (
            f"{name} parsed as {values[name]!r}, not {kind.__name__}. The "
            "assertions below compare it numerically and would raise a "
            "TypeError rather than state what is wrong."
        )
    return values


def test_sync_worker_class_keeps_threads_at_one(config):
    if config["worker_class"] != "sync":
        pytest.skip(f"worker_class is {config['worker_class']!r}, not sync")
    assert config["threads"] == 1, (
        f"worker_class is 'sync' but threads is {config['threads']}. gunicorn "
        "resolves that combination to gthread.ThreadWorker silently, so this "
        "deployment would run a thread pool while the config says otherwise. "
        "Raise concurrency with `workers`, not `threads`."
    )


def test_concurrency_comes_from_processes(config):
    assert config["workers"] >= 4, (
        f"workers={config['workers']}. Sync workers serve one request each, so "
        "this is the service's entire concurrency limit; #13 established that a "
        "slow database takes auth fully offline when it is too low."
    )


def test_pool_is_sized_for_the_worker_model(config):
    from auth.config import DatabaseType, get_settings
    from auth.database import DatabaseEngine

    settings = get_settings()
    if settings.database_type != DatabaseType.POSTGRESQL:
        pool, overflow = 2, 2
    else:
        pool, overflow = DatabaseEngine()._calculate_pool_size()
    per_worker = pool + overflow
    total = config["workers"] * per_worker
    assert total <= 100, (
        f"{config['workers']} workers x {per_worker} connections = {total}, "
        "which is a large share of PostgreSQL's max_connections=200 shared "
        "with every other service on that host"
    )
