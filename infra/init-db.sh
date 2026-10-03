#!/bin/sh
set -eu
# psql variable quoting handles values as SQL literals/identifiers, not code.
psql --username "$POSTGRES_USER" --dbname postgres --set=ON_ERROR_STOP=1 --set=app_user="$APP_DB_USER" --set=app_password="$APP_DB_PASSWORD" --set=app_db="$APP_DB_NAME" <<'SQL'
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE :"app_db" OWNER :"app_user";
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"app_db" TO :"app_user";
SQL
