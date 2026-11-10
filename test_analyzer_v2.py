from analyzer_v2 import analyze
report = analyze("teste_ordem.log")
assert report["events"] == 2
assert report["alerts"] == []

