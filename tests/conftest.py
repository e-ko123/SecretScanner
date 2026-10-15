"""Shared pytest settings. pytest loads this file automatically before the tests.

Parametrized tests get names built from their parameters, like
test_x[AKIA...]. Those names appear in pytest's output, CI logs, and the
.pytest_cache folder. Our parameters include fake keys, and a complete
fake key in a log is exactly what this project tells people never to
write down. So long text parameters get shortened names instead.
"""


def pytest_make_parametrize_id(config, val, argname):
    """Name a long text parameter by its first 4 characters, e.g. "AKIA...".

    pytest calls this "hook" function for every parameter value. Returning
    None means "use pytest's normal name" (fine for short values and
    numbers). If two shortened names clash, pytest adds 0, 1, 2... itself.
    """
    if isinstance(val, str) and len(val) > 12:
        return val[:4] + "..."
    return None
