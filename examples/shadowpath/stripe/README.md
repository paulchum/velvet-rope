# Real Stripe execution path

Run the actual Velvet Rust proxy against Stripe's official hosted MCP server, attempt the
same refund via an explicitly available REST credential, and inspect Stripe's own refund
records with a separate restricted observer key.

The entry point is `python src/velvet/stripe_shadowpath.py run --help`.
See [setup, credentials, test commands, evidence, and boundaries](../../../docs/public/integrations/stripe.md).

`proxy.json` is a local **deny-all Stripe write-tool baseline**, not a production refund
policy. It uses the existing proxy policy-bundle loader, local evidence configuration, and
an actual authenticated upstream. No synthetic Stripe server is started by these commands.
