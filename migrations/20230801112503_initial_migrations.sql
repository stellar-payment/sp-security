create table partner_keypair (
    id bigint unsigned primary key auto_increment,
    partner_id bigint unsigned not null,
    public_key text not null,
    keypair_hash char(64) not null,
    created_at datetime not null,
    updated_at datetime not null
);
create table master_keypair (
    id bigint unsigned primary key auto_increment,
    public_key text not null,
    private_key text not null,
    keypair_hash char(64) not null,
    created_at datetime not null,
    updated_at datetime not null
);