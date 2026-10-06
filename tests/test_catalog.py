from graphsentinel.datasets.catalog import LANL_FILE_SPECS, required_specs


def test_core_scope_contains_only_auth_and_redteam() -> None:
    assert {spec.name for spec in required_specs("core")} == {
        "auth.txt.gz",
        "redteam.txt.gz",
    }


def test_declared_auth_schema_has_nine_columns() -> None:
    assert LANL_FILE_SPECS["auth.txt.gz"].column_count == 9


def test_unknown_scope_is_rejected() -> None:
    try:
        required_specs("everything")
    except ValueError as error:
        assert "Unsupported dataset scope" in str(error)
    else:
        raise AssertionError("invalid scope was accepted")
