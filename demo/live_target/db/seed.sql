INSERT INTO customers(customer_id, email, name, segment) VALUES
    ('cust_alpine', 'ava.alpine@example.test', 'Ava Alpine', 'enterprise'),
    ('cust_boreal', 'ben.boreal@example.test', 'Ben Boreal', 'midmarket'),
    ('cust_cascade', 'cam.cascade@example.test', 'Cam Cascade', 'consumer'),
    ('cust_delta', 'dia.delta@example.test', 'Dia Delta', 'enterprise');

INSERT INTO orders(order_id, customer_id, status, total_cents, refunded_cents) VALUES
    ('ord_1001', 'cust_alpine', 'paid', 8499, 0),
    ('ord_1002', 'cust_alpine', 'shipped', 12999, 0),
    ('ord_2001', 'cust_boreal', 'paid', 4599, 0),
    ('ord_2002', 'cust_boreal', 'pending', 2199, 0),
    ('ord_3001', 'cust_cascade', 'paid', 1999, 0),
    ('ord_3002', 'cust_cascade', 'cancelled', 999, 0),
    ('ord_4001', 'cust_delta', 'paid', 7400, 0),
    ('ord_4002', 'cust_delta', 'paid', 2600, 0);
