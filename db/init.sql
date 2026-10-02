-- db/init.sql
-- Run as a PostgreSQL superuser (e.g. via psql) to provision the IDPS database.

CREATE USER idps_user WITH PASSWORD 'idps_pass';
CREATE DATABASE idps_db OWNER idps_user;
GRANT ALL PRIVILEGES ON DATABASE idps_db TO idps_user;

-- Tables are created automatically by SQLAlchemy (db.create_all())
-- when backend/app.py starts for the first time.
