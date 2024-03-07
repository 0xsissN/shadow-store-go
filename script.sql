CREATE DATABASE shadowstoredb;
USE shadowstoredb;

CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    hash_pass VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    activate TINYINT(1) NOT NULL,
    ver_pass VARCHAR(255) NOT NULL,
    timeout_user DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY id_UNIQUE(id),
    UNIQUE KEY username_UNIQUE(username) 
);