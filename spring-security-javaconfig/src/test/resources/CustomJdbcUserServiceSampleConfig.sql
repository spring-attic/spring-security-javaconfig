create table users(principal varchar_ignorecase(50) not null primary key,credentials varchar_ignorecase(50) not null);
create table roles (principal varchar_ignorecase(50) not null,role varchar_ignorecase(50) not null,constraint fk_roles_users foreign key(principal) references users(principal));
create unique index ix_auth_principal on roles (principal,role);

insert into users values('user','password');
insert into roles values('user','USER');