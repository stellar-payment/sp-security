create table partners (
    id uuid primary key,
    name varchar(255) not null,
    address text not null,
    phone varchar(30) not null,
    email varchar(255) not null,
    pic_name varchar(255) not null,
    pic_email varchar(255) not null,
    pic_phone varchar(30) not null,
    partner_secret char(64) not null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    deleted_at timestamp with time zone
);
create table partner_keypairs (
    id uuid primary key,
    partner_id uuid not null,
    public_key text not null,
    keypair_hash varchar(64) not null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    deleted_at timestamp with time zone
);
create table master_keypairs (
    id uuid primary key,
    public_key text not null,
    private_key text not null,
    keypair_hash varchar(64) not null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    deleted_at timestamp with time zone
);