CREATE DATABASE jwkporterdb;
CREATE USER jwkporterusr WITH PASSWORD 'jwkporterpwd';
GRANT ALL PRIVILEGES ON DATABASE jwkporterdb TO jwkporterusr;

\c jwkporterdb;
GRANT ALL ON SCHEMA public TO jwkporterusr;
