-- Integration fixture: roles, grants, RLS, and sample data.
-- Executed once when the Postgres container starts.

CREATE SCHEMA analytics;
CREATE TABLE analytics.orders (
    id     serial PRIMARY KEY,
    region text   NOT NULL,
    amount numeric NOT NULL
);
INSERT INTO analytics.orders (region, amount) VALUES
    ('eu', 100), ('eu', 200), ('us', 300), ('us', 400);
COMMENT ON COLUMN analytics.orders.region IS 'Sales region code';
COMMENT ON TABLE analytics.orders IS 'Fact table of orders';

-- A schema the target role intentionally has NO access to (tests schema isolation).
CREATE SCHEMA secret;
CREATE TABLE secret.vault (id int, token text);
INSERT INTO secret.vault VALUES (1, 'supersecret');

-- Pool login role: NOT superuser, NOT the owner of the tables above (owner = postgres).
CREATE ROLE mcp_gateway LOGIN PASSWORD 'mcp_pass';

-- Role that actually holds the read grants.
CREATE ROLE read_analyst NOLOGIN;

-- mcp_gateway must be a member so that SET LOCAL ROLE read_analyst succeeds.
GRANT read_analyst TO mcp_gateway;

-- Schema + table level access.
GRANT USAGE ON SCHEMA analytics TO read_analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO read_analyst;
-- NOTE: schema `secret` is deliberately NOT granted.

-- Row level security: region is derived from the per-user identity the MCP sets
-- via set_config('app.user_email', <email>, true).
ALTER TABLE analytics.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_region ON analytics.orders
    USING (region = split_part(current_setting('app.user_email', true), '@', 2));
