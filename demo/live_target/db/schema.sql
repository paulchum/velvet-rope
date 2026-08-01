DROP TABLE IF EXISTS live_demo_dispatch_audit;
DROP TABLE IF EXISTS live_demo_execution_permit_claims;
DROP TABLE IF EXISTS live_demo_control;
DROP TABLE IF EXISTS refunds;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS customers;
DROP TABLE IF EXISTS refund_budget;

CREATE TABLE customers (
    customer_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    segment TEXT NOT NULL,
    deleted_at TIMESTAMPTZ
);

CREATE TABLE orders (
    order_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'shipped', 'cancelled', 'refunded')),
    total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
    refunded_cents INTEGER NOT NULL DEFAULT 0 CHECK (refunded_cents >= 0)
);

CREATE TABLE refunds (
    refund_id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
    customer_id TEXT NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    admitted_action_hash TEXT NOT NULL,
    attempted_action_hash TEXT NOT NULL
);

CREATE TABLE refund_budget (
    account TEXT PRIMARY KEY,
    cap_cents INTEGER NOT NULL CHECK (cap_cents >= 0),
    spent_cents INTEGER NOT NULL DEFAULT 0 CHECK (spent_cents >= 0)
);

CREATE TABLE live_demo_dispatch_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attack TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    admitted_action_hash TEXT,
    attempted_action_hash TEXT,
    admitted_arguments_hash TEXT,
    attempted_arguments_hash TEXT,
    admitted_tool_schema_hash TEXT,
    attempted_tool_schema_hash TEXT,
    admitted_policy_hash TEXT,
    attempted_policy_hash TEXT,
    db_state_hash_before TEXT,
    db_state_hash_after TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE live_demo_execution_permit_claims (
    permit_id TEXT PRIMARY KEY,
    permit_hash TEXT NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tool_name TEXT NOT NULL,
    request_hash TEXT NOT NULL
);

CREATE TABLE live_demo_control (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO refund_budget(account, cap_cents, spent_cents)
VALUES ('refunds:global', 10000, 0);

INSERT INTO live_demo_control(key, value) VALUES
    ('schema_version', '1'),
    ('policy_hash', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
