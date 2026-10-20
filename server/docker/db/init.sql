DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'operator') THEN
        CREATE USER operator WITH PASSWORD 'changeme_replaced_by_setup_permissions';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE ops TO operator;