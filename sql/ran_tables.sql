CREATE TABLE client (
    uuid CHAR(36) PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(64) NOT NULL,
    owner VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    enabled BOOLEAN NOT NULL,
    account_expired BOOLEAN NOT NULL,
    account_locked BOOLEAN NOT NULL
);
CREATE TABLE scope (
    uuid CHAR(36) PRIMARY KEY,
    scope VARCHAR(64) NOT NULL,
    name VARCHAR(32) NOT NULL,
    description VARCHAR(64),
    created_at TIMESTAMP NOT NULL,
    active BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_scope ON scope(scope);
CREATE TABLE client_scope (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    client_uuid CHAR(36) NOT NULL,
    scope_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_client_scope_xref_id FOREIGN KEY (client_uuid) REFERENCES client (uuid),
    CONSTRAINT fk_scope_client_xref_id FOREIGN KEY (scope_uuid) REFERENCES scope (uuid)
);
CREATE UNIQUE INDEX idx_client_scope_xref ON client_scope(client_uuid);
CREATE UNIQUE INDEX idx_scope_client_xref ON client_scope(scope_uuid);