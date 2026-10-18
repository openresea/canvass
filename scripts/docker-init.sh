#!/bin/sh
# Runs only for a new PostgreSQL volume. All values are psql-quoted literals.
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
CREATE DATABASE canvass_ops;
CREATE DATABASE canvass_answers;
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname canvass_ops -f /schemas/ops.sql
psql -v ON_ERROR_STOP=1 --username postgres --dbname canvass_answers -f /schemas/answers.sql
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres \
  -v ops_admin_password="$OPS_ADMIN_PASSWORD" -v ops_canvasser_password="$OPS_CANVASSER_PASSWORD" \
  -v answers_admin_password="$ANSWERS_ADMIN_PASSWORD" -v answers_writer_password="$ANSWERS_WRITER_PASSWORD" <<'SQL'
ALTER ROLE ops_admin PASSWORD :'ops_admin_password';
ALTER ROLE ops_canvasser PASSWORD :'ops_canvasser_password';
ALTER ROLE answers_admin PASSWORD :'answers_admin_password';
ALTER ROLE answers_writer PASSWORD :'answers_writer_password';
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname canvass_ops -v admin_email="$ADMIN_EMAIL" <<'SQL'
INSERT INTO boroughs(borough_id,name) VALUES ('LOCAL','Local region');
INSERT INTO areas(area_id,borough_id,name) VALUES ('LOCAL_CENTRAL','LOCAL','Central area');
INSERT INTO users(email,role) VALUES (lower(:'admin_email'),'GLOBAL_ADMIN');
SQL
