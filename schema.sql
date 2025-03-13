create table account (
    id integer primary key,
    username text unique not null,
    password_hash text not null,
    bio text not null default '',
    location text not null default '',
    image text not null default '',
    link text not null default '',
    created_at integer not null default (unixepoch()),
    docked_at integer not null default (unixepoch())
);

create table follow (
    id integer primary key,
    follower_id integer not null,
    following_id integer not null,
    created_at integer not null default (unixepoch()),
    unique (follower_id, following_id),
    foreign key (follower_id) references account(id),
    foreign key (following_id) references account(id)
);

create table log (
    id integer primary key,
    author_id integer not null,
    content text not null,
    created_at integer not null default (unixepoch()),
    foreign key (author_id) references account(id)
);

create table thumbs (
    id integer primary key,
    liker_id integer not null,
    log_id integer not null,
    created_at integer not null default (unixepoch()),
    unique (liker_id, log_id),
    foreign key (liker_id) references account(id),
    foreign key (log_id) references log(id)
);

create table reply (
    id integer primary key,
    author_id integer not null,
    log_id integer not null,
    content text not null,
    created_at integer not null default (unixepoch()),
    foreign key (author_id) references account(id),
    foreign key (log_id) references log(id)
);

create table notification (
    id integer primary key,
    account_id integer not null,
    created_at integer not null default (unixepoch()),
    seen_at integer default null,
    content text not null,
    foreign key (account_id) references account(id)
);
