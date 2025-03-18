CREATE TABLE client (
    uuid CHAR(36) PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(64) NOT NULL,
    owner VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    enabled BOOLEAN NOT NULL,
    account_expired BOOLEAN NOT NULL,
    account_locked BOOLEAN NOT NULL,
    slug CHAR(36) NOT NULL
);
CREATE TABLE scope (
    uuid CHAR(36) PRIMARY KEY,
    service_name VARCHAR(32) NOT NULL,
    scope VARCHAR(64) NOT NULL,
    scope_name VARCHAR(32) NOT NULL,
    description VARCHAR(64),
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    active BOOLEAN NOT NULL,
    slug CHAR(36) NOT NULL
);
CREATE INDEX idx_sevice_name ON scope(service_name);
CREATE UNIQUE INDEX idx_scope ON scope(scope);
CREATE TABLE client_scope (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    client_uuid CHAR(36) NOT NULL,
    scope_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP,
    CONSTRAINT fk_client_scope_xref_id FOREIGN KEY (client_uuid) REFERENCES client (uuid),
    CONSTRAINT fk_scope_client_xref_id FOREIGN KEY (scope_uuid) REFERENCES scope (uuid)
);
CREATE INDEX idx_client_scope_xref ON client_scope(client_uuid);
CREATE INDEX idx_scope_client_xref ON client_scope(scope_uuid);
CREATE TABLE refresh (
    uuid CHAR(36) PRIMARY KEY,
    refresh_index VARCHAR(128) NOT NULL,
    service_name VARCHAR(128),
    refresh_token VARCHAR(128) NOT NULL,
    client_uuid VARCHAR(128) NOT NULL,
    client_index VARCHAR(128) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    revoked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_refreshindex ON refresh(refresh_index);
CREATE INDEX idx_client_index ON refresh(client_index);
