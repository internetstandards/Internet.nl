from internetnl.settings_utils import split_csv_trim, get_boolean_env


def test_split_csv_trim():
    assert split_csv_trim("") == []
    assert split_csv_trim("A") == ["A"]
    assert split_csv_trim(" a , b , c ") == ["a", "b", "c"]
    assert split_csv_trim(" 1 , 2 , 3 ") == ["1", "2", "3"]


def test_get_boolean_env_nothing_set():
    assert get_boolean_env("NON_EXISTANT", False) is False
    assert get_boolean_env("NON_EXISTANT", True) is True


def test_get_boolean_env_set_true(monkeypatch):
    # https://dev.to/mhihasan/testing-environment-variable-in-pytest-38ec
    monkeypatch.setenv("NON_EXISTANT", "True")

    assert get_boolean_env("NON_EXISTANT", False) is True
    assert get_boolean_env("NON_EXISTANT", True) is True


def test_get_boolean_env_set_false(monkeypatch):
    # https://dev.to/mhihasan/testing-environment-variable-in-pytest-38ec
    monkeypatch.setenv("NON_EXISTANT", "False")

    assert get_boolean_env("NON_EXISTANT", True) is False
    assert get_boolean_env("NON_EXISTANT", False) is False
