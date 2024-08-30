create table certificates
(
    id             serial,
    uuid           varchar not null unique,
    base64_content varchar null default null,
    meta           text    null default null,
    primary key (id)
);

CREATE INDEX index_certificates_uuid ON certificates (uuid);

create table discoveries
(
    id     serial,
    uuid   varchar not null unique,
    name   varchar not null unique,
    status varchar not null,
    meta   text    null default null,
    primary key (id)
);

create table discovery_certificates
(
    certificate_id bigint not null,
    discovery_id   bigint not null,
    primary key (certificate_id, discovery_id),
    foreign key (certificate_id) references certificates (id),
    foreign key (discovery_id) references discoveries (id) on delete cascade
);
