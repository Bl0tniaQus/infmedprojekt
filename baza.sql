DROP TABLE IF EXISTS uzytkownik CASCADE;
DROP TABLE IF EXISTS wiadomosc CASCADE;
DROP TABLE IF EXISTS zalacznik CASCADE;


CREATE TABLE uzytkownik (
    id_uzytkownika serial PRIMARY KEY,
    nazwa_uzytkownika VARCHAR ( 50 ) UNIQUE NOT NULL,
    haslo CHAR(64) NOT NULL,
    klucz_publiczny bytea NOT NULL,
    data_dolaczenia DATE NOT NULL
);
CREATE TABLE wiadomosc (
	id_wiadomosci serial PRIMARY KEY,
	autor integer NOT NULL,
	adresat integer not null,
	tytul varchar(128) not null,
	tresc bytea not null,
	zalacznik integer,
	szyfr integer not null,
    data_dodania DATE NOT NULL,
    aesiv bytea,
    CONSTRAINT fk_wiadomosc_autor FOREIGN KEY(autor) REFERENCES uzytkownik(id_uzytkownika),
    CONSTRAINT fk_wiadomosc_adresat FOREIGN KEY(adresat) REFERENCES uzytkownik(id_uzytkownika)  
);

CREATE TABLE zalacznik (
id_zalacznika serial primary key,
id_wiadomosci integer not null,
zalacznik bytea not null,
nazwa_pliku varchar(256) not null,
szyfr integer not null,
CONSTRAINT fk_zalacznik FOREIGN KEY(id_wiadomosci) REFERENCES wiadomosc(id_wiadomosci) 
);
