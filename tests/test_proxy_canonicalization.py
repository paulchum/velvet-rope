from __future__ import annotations

from velvet.actions import AuthorityClass
from velvet.contracts import AdmissionContract
from velvet.executor import VelvetAdmissionLayer
from velvet.normalizer import VelvetActionNormalizer


def test_drop_table_sql_proxy_canonicalizes_to_destroy() -> None:
    action = VelvetActionNormalizer().normalize(
        {
            "surface": "sql",
            "sql": "/* maintenance */ DROP TABLE customers",
            "boundary_key": "database:crm:migration:1",
        },
        AdmissionContract(),
    )

    assert action.authority_class is AuthorityClass.DESTROY
    assert action.canonical_type == "drop_table"
    assert action.normalized_payload["proxy_detected"] is True
    assert action.normalized_payload["sql_lift_rule"] == "sql:drop:destroy"


def test_sql_lift_table_maps_core_statement_classes() -> None:
    normalizer = VelvetActionNormalizer()
    contract = AdmissionContract()
    cases = {
        "DELETE FROM customers WHERE id = 1": AuthorityClass.DESTROY,
        "TRUNCATE TABLE customers": AuthorityClass.DESTROY,
        "UPDATE customers SET status = 'inactive'": AuthorityClass.ALTER,
        "INSERT INTO customers(id) VALUES (1)": AuthorityClass.APPEND,
        "CREATE TABLE customer_notes(id int)": AuthorityClass.APPEND,
        "SELECT * FROM customers": AuthorityClass.OBSERVE,
    }

    for sql, authority_class in cases.items():
        action = normalizer.normalize(
            {"surface": "sql", "sql": sql, "boundary_key": "database:crm:migration:1"},
            contract,
        )
        assert action.authority_class is authority_class
        assert action.normalized_payload["sql_ast_kind"]
        assert action.normalized_payload["sql_dialect"] == "postgres"


def test_malformed_sql_becomes_masked_action_failure() -> None:
    outcome = VelvetAdmissionLayer(AdmissionContract(default_authority_budget=10_000)).evaluate(
        {
            "surface": "sql",
            "sql": "SELECT FROM WHERE",
            "boundary_key": "database:crm:migration:1",
        },
        logical_step=1,
    )

    assert outcome.decision.value == "MASKED_ACTION_FAILURE"
    assert outcome.canonical_action.authority_class is AuthorityClass.DESTROY
