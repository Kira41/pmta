import shiva


def test_coerce_scalar_number_handles_list_values():
    assert shiva._coerce_scalar_number(["2525"], as_type="int", default=25) == 2525
    assert shiva._coerce_scalar_number(["0.35"], as_type="float", default=0.0) == 0.35


def test_coerce_scalar_number_falls_back_on_invalid_values():
    assert shiva._coerce_scalar_number([], as_type="int", default=50) == 50
    assert shiva._coerce_scalar_number([{"bad": 1}], as_type="float", default=1.5) == 1.5
