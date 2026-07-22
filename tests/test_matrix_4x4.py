from cyberdeck.analysis.risk_engine import matrix_4x4


def test_matrix_band_edges():
    assert matrix_4x4(0.0, 0.0)["matrix_score"] == 1
    assert matrix_4x4(0.24, 0.24)["label"] == "Bajo"
    assert matrix_4x4(0.50, 0.50)["matrix_score"] == 4
    assert matrix_4x4(0.76, 0.76)["label"] == "Critico"
