-- auto-generated definition
create table oauth_client_details
(
    client_id               varchar(128)  not null
        primary key,
    resource_ids            varchar(256)  null,
    client_secret           varchar(256)  null,
    scope                   varchar(256)  null,
    authorized_grant_types  varchar(256)  null,
    web_server_redirect_uri varchar(2560) null,
    authorities             varchar(256)  null,
    access_token_validity   int           null,
    refresh_token_validity  int           null,
    additional_information  varchar(4096) null,
    autoapprove             varchar(256)  null
)
    charset = utf8;



-- auto-generated definition
create table t_admin
(
    id                 int auto_increment
        primary key,
    user_name          varchar(128)                       null,
    password           varchar(128)                       null,
    level              varchar(12)                        null comment 'USER,ANALYST,ROOT',
    group_id           varchar(64)                        null comment '用户所属的组',
    deleted            tinyint  default 0                 null comment '0：未删除，1：已删除',
    create_time        datetime default CURRENT_TIMESTAMP null,
    update_time        datetime                           null on update CURRENT_TIMESTAMP,
    status             tinyint  default 1                 null comment '1：正常，2：停用',
    tenant_id          int                                null,
    authorization_code varchar(512)                       null comment '授权编码',
    authorization_date datetime                           null,
    constraint t_admin_user_name_uindex
        unique (user_name,deleted)
)
    comment '用户信息' charset = utf8;

