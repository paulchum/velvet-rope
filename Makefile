LIVE_DEMO_COMPOSE ?= demo/live_target/docker-compose.yml

.PHONY: seal-conformance live-demo live-demo-db-up live-demo-suite live-demo-incident live-demo-down live-demo-argument-drift live-demo-schema-drift live-demo-approval-replay live-demo-policy-swap live-demo-budget-overshoot live-demo-signer-kill underwriter-review-bundle

seal-conformance:
	uv run pytest tests/test_seal_conformance.py -q

live-demo-db-up:
	docker compose -f $(LIVE_DEMO_COMPOSE) up -d

live-demo-suite:
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.run_suite

live-demo-incident:
	uv run python -m demo.incident.run

live-demo: live-demo-db-up live-demo-suite live-demo-incident

underwriter-review-bundle:
	uv run velvet underwriter-bundle --json

live-demo-down:
	docker compose -f $(LIVE_DEMO_COMPOSE) down

live-demo-argument-drift: live-demo-db-up
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.argument_drift

live-demo-schema-drift: live-demo-db-up
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.schema_drift

live-demo-approval-replay: live-demo-db-up
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.approval_replay

live-demo-policy-swap: live-demo-db-up
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.policy_swap

live-demo-budget-overshoot: live-demo-db-up
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.budget_overshoot

live-demo-signer-kill: live-demo-db-up
	cargo build -q -p velvet-rope-proxy
	uv run python -m demo.attacks.signer_kill
