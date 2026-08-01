from __future__ import annotations

from velvet.contracts import AdmissionContract
from velvet.fallback import VelvetFallbackCompiler
from velvet.normalizer import VelvetActionNormalizer


def test_fallback_compiler_is_idempotent() -> None:
    action = VelvetActionNormalizer().normalize(
        {
            "surface": "function",
            "name": "update_customer",
            "boundary_key": "case:1",
            "target_resource": "customer:1",
        },
        AdmissionContract(),
    )
    compiler = VelvetFallbackCompiler()
    fallback = compiler.compile(action)

    assert compiler.compile(fallback) == fallback
    assert fallback.fallback_type == "dry_run_diff"
