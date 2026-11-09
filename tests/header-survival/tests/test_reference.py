"""The sketch's outputs still reproduce with the harness present."""

import subprocess
import sys

from survival.reference import ROOT, SKETCH, ref


def test_every_delivery_passes():
    results = ref.run(ref.vectors())
    assert len(results) == 123
    assert [(n, i, w, g) for n, i, w, g in results if w != g] == []


def test_vectors_json_reproduces():
    out = subprocess.run([sys.executable, str(SKETCH), "--json"], capture_output=True, check=True)
    assert out.stdout == (ROOT / "reference" / "vectors.json").read_bytes()


def test_example_reproduces():
    out = subprocess.run(
        [sys.executable, str(SKETCH), "--example"], capture_output=True, check=True
    )
    assert out.stdout == (ROOT / "reference" / "example.txt").read_bytes()
