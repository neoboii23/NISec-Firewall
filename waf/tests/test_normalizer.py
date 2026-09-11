from engine.normalizer import Normalizer


def test_repeated_url_and_html_decoding_is_bounded_and_detectable():
    value = Normalizer().normalize("%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E")
    assert value.normalized_value == "<script>alert(1)</script>"
    assert value.passes == 2


def test_normalizer_preserves_raw_value_and_normalizes_slashes():
    value = Normalizer().normalize("..\\etc\\passwd\x00")
    assert value.raw_value.endswith("\x00")
    assert value.normalized_value == "../etc/passwd"
