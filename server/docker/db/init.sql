DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'operator') THEN
        CREATE USER operator;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE ops TO operator;