-- Market schema

CREATE TABLE selling(
    id INTEGER PRIMARY KEY NOT NULL,
    seller TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE buying(
    id INTEGER PRIMARY KEY NOT NULL,
    buyer TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL
);
