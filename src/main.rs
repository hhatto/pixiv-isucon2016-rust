#[macro_use]
extern crate nickel;
extern crate multipart;
extern crate mysql;
extern crate nickel_mysql;
extern crate nickel_jwt_session;
extern crate hyper;
extern crate nickel_tera;
extern crate tera;
extern crate serde;
extern crate regex;
extern crate time;
extern crate rustc_serialize;
extern crate rand;
extern crate mime;

use std::str::FromStr;
use std::process::Command;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::collections::BTreeMap;
use multipart::server::{Entries, Multipart, SaveResult};
use nickel::{Nickel, HttpRouter, Request, Response, Middleware, MiddlewareResult, NickelError, Action,
             StaticFilesHandler, FormBody};
// use nickel::MediaType;
use nickel::status::StatusCode;
use nickel::extensions::Redirect;
use nickel_mysql::{MysqlMiddleware, MysqlRequestExtensions};
use nickel_jwt_session::{SessionMiddleware, SessionRequestExtensions, SessionResponseExtensions};
use nickel_tera::{TeraMiddleware, TeraRequestExtensions};
use mime::{Attr, Mime};
use hyper::header;
use tera::Context;
use mysql::value::from_value;
use regex::Regex;
use time::Timespec;
use rustc_serialize::json::ToJson;

const DB_NAME: &'static str = "isuconp";
const DB_USER: &'static str = "root";

struct Logger;

impl<D> Middleware<D> for Logger {
    fn invoke<'mw, 'conn>(&self, req: &mut Request<'mw, 'conn, D>, res: Response<'mw, D>) -> MiddlewareResult<'mw, D> {
        println!("{} {} ::: {:?}", req.origin.method, req.origin.uri, res.status());
        res.next_middleware()
    }
}

fn custom_handler<D>(err: &mut NickelError<D>, req: &mut Request<D>) -> Action {
    println!("|  - {} {} Error: {:?}", req.origin.method, req.origin.uri, err.message);
    Action::Continue(())
}

#[derive(Default, Debug)]
struct Comment {
    id: u32,
    post_id: u32,
    user_id: u32,
    comment: String,
    created_at: String,
    user: User,
}

impl serde::Serialize for Comment {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        let mut state = try!(serializer.serialize_struct("Comment", 5));
        try!(serializer.serialize_struct_elt(&mut state, "id", &self.id));
        try!(serializer.serialize_struct_elt(&mut state, "post_id", &self.post_id));
        try!(serializer.serialize_struct_elt(&mut state, "user_id", &self.user_id));
        try!(serializer.serialize_struct_elt(&mut state, "comment", &self.comment));
        try!(serializer.serialize_struct_elt(&mut state, "created_at", &self.created_at));
        try!(serializer.serialize_struct_elt(&mut state, "user", &self.user));
        serializer.serialize_struct_end(state)
    }
}

#[derive(Default, Debug)]
struct Post {
    id: u32,
    user_id: u32,
    mime: String,
    imgdata: Vec<u8>,
    body: String,
    created_at: String,
    image_url: String,
    nl2br_body: String,
    comment_count: u32,
    user: User,
    comments: Vec<Comment>,
    csrf_token: String,
}

impl serde::Serialize for Post {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        let mut state = try!(serializer.serialize_struct("Post", 12));
        try!(serializer.serialize_struct_elt(&mut state, "id", &self.id));
        try!(serializer.serialize_struct_elt(&mut state, "user_id", &self.user_id));
        try!(serializer.serialize_struct_elt(&mut state, "mime", &self.mime));
        try!(serializer.serialize_struct_elt(&mut state, "imgdata", &self.imgdata));
        try!(serializer.serialize_struct_elt(&mut state, "body", &self.body));
        try!(serializer.serialize_struct_elt(&mut state, "created_at", &self.created_at));
        try!(serializer.serialize_struct_elt(&mut state, "image_url", &self.image_url));
        try!(serializer.serialize_struct_elt(&mut state, "nl2br_body", &self.nl2br_body));
        try!(serializer.serialize_struct_elt(&mut state, "comment_count", &self.comment_count));
        try!(serializer.serialize_struct_elt(&mut state, "user", &self.user));
        try!(serializer.serialize_struct_elt(&mut state, "comments", &self.comments));
        try!(serializer.serialize_struct_elt(&mut state, "csrf_token", &self.csrf_token));
        serializer.serialize_struct_end(state)
    }
}

#[derive(Default, Debug)]
struct User {
    id: u32,
    account_name: String,
    passhash: String,
    authority: u32,
    del_flg: u32,
    created_at: String,
}

impl User {
    fn is_login(&self) -> bool {
        self.id != 0
    }
}

impl serde::Serialize for User {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        let mut state = try!(serializer.serialize_struct("User", 6));
        try!(serializer.serialize_struct_elt(&mut state, "id", &self.id));
        try!(serializer.serialize_struct_elt(&mut state, "account_name", &self.account_name));
        try!(serializer.serialize_struct_elt(&mut state, "passhash", &self.passhash));
        try!(serializer.serialize_struct_elt(&mut state, "authority", &self.authority));
        try!(serializer.serialize_struct_elt(&mut state, "del_flg", &self.del_flg));
        try!(serializer.serialize_struct_elt(&mut state, "created_at", &self.created_at));
        serializer.serialize_struct_end(state)
    }
}

fn process_entries<'mw>(db_conn: Arc<mysql::Pool>, user: User, mut res: Response<'mw>, session_csrf_token: String, entries: Entries) -> MiddlewareResult<'mw> {
    let mut csrf_token = "".to_string();
    let mut body = "".to_string();
    for (name, field) in entries.fields {
        println!(r#"Field "{}": "{}""#, name, field);
        if name == "body" {
            body = field;
        } else if name == "csrf_token" {
            csrf_token = field;
        }
    }

    println!("csrf={}, s-csrf={}, body={}", csrf_token, session_csrf_token, body);

    if session_csrf_token != csrf_token {
        res.set(StatusCode::UnprocessableEntity);
        return res.send("");
    }

    let mime = "image/jpeg";

    for (name, savedfile) in entries.files {
        let filename = match savedfile.filename {
            Some(s) => s,
            None => "None".into(),
        };

        println!("s-path={:?}", savedfile.path);
        match File::open(savedfile.path) {
            Ok(mut file) => {
                let mut contents: Vec<u8> = vec![];
                match file.read_to_end(&mut contents) {
                    Ok(sz) => {
                        println!("File: \"{}\" is of size: {}b.", filename, sz);
                        let query = "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)";
                        let row = db_conn.prep_exec(query, (user.id, mime, contents, body)).unwrap();
                        return res.redirect(format!("/posts/{}", row.last_insert_id()));
                    },
                    Err(e) => println!("Could not read file's \"{}\" size. Error: {:?}", filename, e),
                }
                println!(r#"Field "{}" is file "{}":"#, name, filename);
                file
            }
            Err(e) => {
                println!("Could open file \"{}\". Error: {:?}", filename, e);
                return res.error(StatusCode::BadRequest, "The uploaded file was not readable");
            }
        };
    }

    res.send("Ok")
}

fn image_url(id: u32, mime: &str) -> String {
    let base = format!("/image/{}", id);
    if mime == "image/jpeg" {
        format!("{}.jpg", base)
    } else if mime == "image/png" {
        format!("{}.png", base)
    } else if mime == "image/gif" {
        format!("{}.gif", base)
    } else {
        base
    }
}

fn get_csrf_token(req: &mut Request) -> String {
    match req.valid_custom_claims() {
        None => "".to_string(),
        Some(v) => {
            match v.get("csrf_token") {
                None => "".to_string(),
                Some(v) => v.as_string().unwrap().to_string(),
            }
        }
    }
}

fn make_posts(db_conn: Arc<mysql::Pool>, posts: &mut Vec<Post>, csrf_token: String, all_comments: bool) -> Result<(), &'static str> {
    for mut post in posts {
        // comment count
        let comment_query = "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?";
        let comment_count = from_value(db_conn.prep_exec(comment_query, vec![post.id])
                                       .unwrap().next().unwrap().unwrap().unwrap().pop().unwrap());
        post.comment_count = comment_count;

        // post comment
        let mut query = "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC".to_string();
        if !all_comments {
            query = format!("{} LIMIT 3", query);
        }
        let comments: Vec<Comment> = db_conn.prep_exec(query.as_str(), vec![post.id])
            .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        Comment {
                            id: from_value(row.take("id").unwrap()),
                            post_id: from_value(row.take("post_id").unwrap()),
                            user_id: from_value(row.take("user_id").unwrap()),
                            comment: from_value(row.take("comment").unwrap()),
                            ..Comment::default()
                        }
                    })
                    .collect()
            })
            .unwrap();
        // comment user
        for mut comment in comments {
            let mut users: Vec<User> = db_conn.prep_exec("SELECT * FROM `users` WHERE `id` = ?", vec![post.user_id])
                .map(|ret| {
                    ret.map(|x| x.unwrap())
                        .map(|mut row| {
                            User {
                                id: from_value(row.take("id").unwrap()),
                                account_name: from_value(row.take("account_name").unwrap()),
                                ..User::default()
                            }
                        })
                        .collect()
                })
                .unwrap();
            let u = users.pop().unwrap();
            comment.user = User {
                id: u.id,
                account_name: u.account_name,
                ..User::default()
            };
        }

        // post user
        let mut users: Vec<User> = db_conn.prep_exec("SELECT * FROM `users` WHERE `id` = ?", vec![post.user_id])
            .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        User {
                            id: from_value(row.take("id").unwrap()),
                            account_name: from_value(row.take("account_name").unwrap()),
                            ..User::default()
                        }
                    })
                    .collect()
            })
            .unwrap();
        let u = users.pop().unwrap();
        post.user = User {
            id: u.id,
            account_name: u.account_name,
            ..User::default()
        };
        post.csrf_token = csrf_token.to_owned();
    }
    Ok(())
}

fn get_session_user(req: &mut Request) -> User {
    let db_conn = req.db_connection();
    match req.valid_custom_claims() {
        None => User { ..User::default() },
        Some(v) => {
            let t = v.get("user_id");
            if t.is_none() {
                return User { ..User::default() };
            }
            let uid = t.unwrap().as_u64().unwrap();
            let query = "SELECT * FROM `users` WHERE `id` = ?";
            let mut row = db_conn.prep_exec(query, vec![uid]).unwrap();
            match row.next() {
                Some(v) => {
                    let (id, account_name, passhash, authority, del_flg, created_at): (u32,
                                                                                       String,
                                                                                       String,
                                                                                       u32,
                                                                                       u32,
                                                                                       Timespec) =
                        mysql::from_row(v.unwrap());
                    let tm = time::at_utc(created_at);
                    let c = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm);
                    User {
                        id: id,
                        account_name: account_name,
                        passhash: passhash,
                        authority: authority,
                        del_flg: del_flg,
                        created_at: c.unwrap(),
                        ..User::default()
                    }
                }
                None => User { ..User::default() },
            }
        }
    }
}

fn escape_shellarg(src: &str) -> String {
    src.replace("'", "'\\''")
}

fn digest(src: &str) -> String {
    let es = escape_shellarg(src);
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(format!("{}{}{}", "printf \"%s\" ", es, " | openssl dgst -sha512 | sed 's/^.*= //'"))
        .output()
        .expect("fail");
    let s = String::from_utf8(output.stdout).unwrap().as_str().trim().to_string();
    s
}

fn calculate_salt(username: &str) -> String {
    return digest(username);
}

fn calculate_passhash(username: &str, password: &str) -> String {
    let h = format!("{}:{}", password.to_string(), calculate_salt(username));
    return digest(h.as_str());
}

fn try_login(db_conn: Arc<mysql::Pool>, username: &str, password: &str) -> Option<User> {
    let query = "SELECT * FROM users WHERE account_name = ? AND del_flg = 0";
    let mut row = db_conn.prep_exec(query, vec![username]).unwrap();
    let user = match row.next() {
        Some(v) => {
            let (id, account_name, passhash, authority, del_flg, created_at): (u32,
                                                                               String,
                                                                               String,
                                                                               u32,
                                                                               u32,
                                                                               Timespec) =
                mysql::from_row(v.unwrap());
            let tm = time::at_utc(created_at);
            let c = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm);
            Some(User {
                id: id,
                account_name: account_name,
                passhash: passhash,
                authority: authority,
                del_flg: del_flg,
                created_at: c.unwrap(),
                ..User::default()
            })
        }
        None => None,
    };

    if user.is_some() {
        let u = user.unwrap();
        if calculate_passhash(u.account_name.as_str(), password) == u.passhash {
            return Some(u);
        } else {
            return None;
        }
    }
    None
}

fn get_login<'mw>(req: &mut Request, res: Response<'mw>) -> MiddlewareResult<'mw> {
    let me = get_session_user(req);
    if me.is_login() {
        return res.redirect("/");
    }

    let message = match req.valid_custom_claims() {
        None => "",
        Some(v) => {
            match v.get("notice") {
                None => "",
                Some(v) => v.as_string().unwrap(),
            }
        }
    };
    let mut ctx = Context::new();
    ctx.add("messages", &message);
    ctx.add("me", &me);
    res.send(req.template_engine().render("login.html", ctx).unwrap())
}

fn post_login<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let me = get_session_user(req);
    let db_conn = req.db_connection();
    if me.is_login() {
        return res.redirect("/");
    }
    let form_data = try_with!(res, req.form_body());
    let account_name = form_data.get("account_name").unwrap();
    let password = form_data.get("password").unwrap();
    let user = try_login(db_conn, account_name, password);

    match user {
        None => {
            let message = "アカウント名かパスワードが間違っています";
            let mut d = BTreeMap::new();
            d.insert("notice".to_owned(), message.to_json());
            res.set_jwt_user_and_custom_claims("isu", d);
            res.redirect("/login")
        }
        Some(u) => {
            let csrf_token = format!("{}", rand::random::<u32>());
            let mut d = BTreeMap::new();
            let uid = u.id;
            d.insert("user_id".to_owned(), uid.to_json());
            d.insert("csrf_token".to_owned(), csrf_token.to_json());
            res.set_jwt_user_and_custom_claims("isu", d);
            res.redirect("/")
        }
    }
}

fn get_image<'mw>(req: &mut Request, res: Response<'mw>) -> MiddlewareResult<'mw> {
    let id = req.param("id").unwrap();
    let db_conn = req.db_connection();
    let query = "SELECT mime, imgdata FROM `posts` WHERE `id` = ?";
    let mut row = db_conn.prep_exec(query, vec![id]).unwrap().next().unwrap().unwrap();
    let imagedata: Vec<u8> = from_value(row.take("imgdata").unwrap());
    // let mime_string: String = from_value(row.take("mime").unwrap());
    // let mime = if (mime_string.as_str() == "image/png") {
    //    MediaType::Png
    // } else if (mime_string.as_str() == "image/jpeg") {
    //   MediaType::Jpeg
    // } else {
    //    MediaType::Gif
    // };
    res.send(imagedata)
}

fn get_account_name<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let csrf_token: String = {
        get_csrf_token(req)
    };
    let me = get_session_user(req);

    let account_name = req.param("name").unwrap();

    let query = "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0";
    let mut users: Vec<User> =
        db_conn.prep_exec(query, vec![account_name.to_owned()])
            .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        let tm = time::at_utc(row.take("created_at").unwrap());
                        let created_at = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm).unwrap();
                        User {
                            id: from_value(row.take("id").unwrap()),
                            account_name: from_value(row.take("account_name").unwrap()),
                            passhash: from_value(row.take("passhash").unwrap()),
                            authority: from_value(row.take("authority").unwrap()),
                            del_flg: from_value(row.take("del_flg").unwrap()),
                            created_at: created_at,
                        }
                    })
                    .collect()
            })
            .unwrap();
    if users.len() != 1 {
        res.set(StatusCode::NotFound);
        return res.send("");
    }
    let user = users.pop().unwrap();
    if user.id == 0 {
        res.set(StatusCode::NotFound);
        return res.send("");
    }

    let posts_query = "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC";
    let mut posts: Vec<Post> = db_conn.prep_exec(posts_query, vec![user.id])
        .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        let id = from_value(row.take("id").unwrap());
                        let mime: String = row.take("mime").unwrap();
                        let body: String = row.take("body").unwrap();
                        let tm = time::at_utc(row.take("created_at").unwrap());
                        let created_at = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm).unwrap();
                        Post {
                            id: id,
                            user_id: from_value(row.take("user_id").unwrap()),
                            image_url: image_url(id, mime.as_str()),
                            mime: mime,
                            // imgdata: "".to_string(),
                            body: body,
                            created_at: created_at,
                            ..Post::default()
                        }
                    })
                    .collect()
    }).unwrap();

    let comment_query = "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?";
    let comment_count: u32 = from_value(db_conn.prep_exec(comment_query, vec![user.id]).unwrap()
                                   .next().unwrap().unwrap().unwrap().pop().unwrap());

    let post_count_query = "SELECT `id` FROM `posts` WHERE `user_id` = ?";
    let c_posts: Vec<Post> = db_conn.prep_exec(post_count_query, vec![user.id])
        .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        let id = from_value(row.take("id").unwrap());
                        Post { id: id, ..Post::default() }
                    })
                    .collect()
    }).unwrap();
    let post_count = c_posts.len();

    let mut commented_count = 0;
    if post_count > 0 {
        let mut pp = vec![];
        let mut vv = vec![];
        for p in c_posts {
            pp.push("?");
            vv.push(p.id);
        }
        let joined = pp.join(", ");
        let commented_query = format!(r"SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ({})", joined);
        commented_count = from_value(db_conn.prep_exec(commented_query.as_str(), vv)
                                       .unwrap().next().unwrap().unwrap().unwrap().pop().unwrap());
    }

    let _ = make_posts(db_conn, &mut posts, csrf_token.to_owned(), false);

    let mut ctx = Context::new();
    let notice = "";
    ctx.add("notice", &notice);
    ctx.add("me", &me);
    ctx.add("user", &user);
    ctx.add("posts", &posts);
    ctx.add("csrf_token", &csrf_token);
    ctx.add("post_count", &post_count);
    ctx.add("comment_count", &comment_count);
    ctx.add("commented_count", &commented_count);
    res.send(req.template_engine().render("user.html", ctx).unwrap())
}

fn get_posts_id<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let csrf_token: String = {
        get_csrf_token(req)
    };
    let me = get_session_user(req);

    let id = req.param("id").unwrap();
    let query = "SELECT * FROM `posts` WHERE `id` = ?";
    let mut posts: Vec<Post> = db_conn.prep_exec(
        query, vec![id]).map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        let id = from_value(row.take("id").unwrap());
                        let mime: String = row.take("mime").unwrap();
                        let body: String = row.take("body").unwrap();
                        let tm = time::at_utc(row.take("created_at").unwrap());
                        let created_at = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm).unwrap();
                        Post {
                            id: id,
                            user_id: from_value(row.take("user_id").unwrap()),
                            image_url: image_url(id, mime.as_str()),
                            mime: mime,
                            // imgdata: "".to_string(),
                            body: body,
                            created_at: created_at,
                            ..Post::default()
                        }
                    })
                    .collect()
    }).unwrap();

    if posts.len() != 1 {
        res.set(StatusCode::NotFound);
        return res.send("");
    }

    let _ = make_posts(db_conn, &mut posts, csrf_token.to_owned(), true);

    let mut ctx = Context::new();
    let notice = "";
    ctx.add("notice", &notice);
    ctx.add("me", &me);
    ctx.add("posts", &posts);
    ctx.add("csrf_token", &csrf_token);
    res.send(req.template_engine().render("posts.html", ctx).unwrap())
}

fn get_index<'mw>(req: &mut Request, res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let csrf_token: String = {
        get_csrf_token(req)
    };
    let me = get_session_user(req);
    let mut posts: Vec<Post> =
        db_conn.prep_exec("SELECT `id`, `user_id`, `body`, `created_at`, `mime` FROM `posts` ORDER \
                        BY `created_at` DESC LIMIT 100",
                       ())
            .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        // let (id, user_id, body, created_at, mime) = mysql::from_row(row);
                        let id = from_value(row.take("id").unwrap());
                        let mime: String = row.take("mime").unwrap();
                        let body: String = row.take("body").unwrap();
                        let tm = time::at_utc(row.take("created_at").unwrap());
                        let created_at = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm).unwrap();
                        Post {
                            id: id,
                            user_id: from_value(row.take("user_id").unwrap()),
                            image_url: image_url(id, mime.as_str()),
                            mime: mime,
                            // imgdata: "".to_string(),
                            body: body,
                            created_at: created_at,
                            ..Post::default()
                        }
                    })
                    .collect()
            })
            .unwrap();

    let _ = make_posts(db_conn, &mut posts, csrf_token.to_owned(), false);

    let mut ctx = Context::new();
    let notice = "";
    ctx.add("notice", &notice);
    ctx.add("me", &me);
    ctx.add("posts", &posts);
    ctx.add("csrf_token", &csrf_token);
    res.send(req.template_engine().render("index.html", ctx).unwrap())
}

fn post_index<'mw>(mut req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let csrf_token: String = {
        get_csrf_token(req)
    };
    let user = get_session_user(req);
    if !user.is_login() {
        println!("post_index() no login");
        return res.redirect("/login");
    }

    {
    let content_type = req.origin.headers.get::<header::ContentType>().unwrap();
    match content_type.get_param(Attr::Q) {
        Some(v) => println!("ctype={:?}", v),
        None => println!("ctype=NotFound"),
    };
    println!("mime={:?}", Mime::from_str("image/jpeg").unwrap());
    //if content_type.get_param(mime::Attr::Q).unwrap() == Mime::from_str("image/jpeg").unwrap() {
    //    mime = "image/jpeg";
    //} else {
    //    // hog
    //};
    }

    let mu = Multipart::from_request(req);

    match mu {
        Ok(mut multipart) => {
            match multipart.save_all() {
                SaveResult::Full(entries) => {
                    process_entries(db_conn, user, res, csrf_token, entries)
                },
                SaveResult::Partial(entries, _) => {
                    return process_entries(db_conn, user, res, csrf_token, entries);
                }
                SaveResult::Error(e) => {
                    res.set(StatusCode::PreconditionFailed);
                    return res.send(format!("Server could not handle multipart POST! {:?}", e));
                }
            }
        }
        Err(_) => {
            res.set(StatusCode::PreconditionFailed);
            return res.next_middleware();
        }
    }
}

fn get_register<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let user = get_session_user(req);
    if user.is_login() {
        res.set(StatusCode::Found);
        return res.redirect("/");
    }
    let message = match req.valid_custom_claims() {
        None => "",
        Some(v) => {
            match v.get("notice") {
                None => "",
                Some(v) => {
                    println!("{}", v);
                    v.as_string().unwrap()
                }
            }
        }
    };
    let mut ctx = Context::new();
    ctx.add("notice", &message);
    ctx.add("me", &User { ..User::default() });
    res.send(req.template_engine().render("register.html", ctx).unwrap())
}

fn validate_user(account_name: &str, password: &str) -> bool {
    let re_name = Regex::new("[0-9a-zA-Z]{3,}").unwrap();
    if !re_name.is_match(account_name) {
        return false;
    }
    let re_passwd = Regex::new("[0-9a-zA-Z_]{6,}").unwrap();
    if !re_passwd.is_match(password) {
        return false;
    }
    true
}

fn post_register<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let me = get_session_user(req);
    if me.is_login() {
        return res.redirect("/");
    }

    let form_data = try_with!(res, req.form_body());
    let account_name = form_data.get("account_name").unwrap().to_string();
    let password = form_data.get("password").unwrap();
    if !validate_user(account_name.as_str(), password) {
        let message = "アカウント名は3文字以上、パスワードは6文字以上である必要があります";
        let mut d = BTreeMap::new();
        d.insert("notice".to_owned(), message.to_json());
        res.set_jwt_user_and_custom_claims("isu", d);
        return res.redirect("/register");
    }

    let result: Vec<User> =
        db_conn.prep_exec("SELECT * FROM users WHERE account_name = ? AND del_flg = 0", vec![account_name.to_owned()])
            .map(|ret| {
                ret.map(|x| x.unwrap())
                    .map(|mut row| {
                        User {
                            id: from_value(row.take("id").unwrap()),
                            account_name: from_value(row.take("account_name").unwrap()),
                            passhash: from_value(row.take("passhash").unwrap()),
                            authority: from_value(row.take("authority").unwrap()),
                            del_flg: from_value(row.take("del_flg").unwrap()),
                            created_at: from_value(row.take("created_at").unwrap()),
                        }
                    })
                    .collect()
            })
            .unwrap();

    if result.len() == 1 {
        let message = "アカウント名がすでに使われています";
        let mut d = BTreeMap::new();
        d.insert("notice".to_owned(), message.to_json());
        res.set_jwt_user_and_custom_claims("isu", d);
        return res.redirect("/register");
    }

    let query = "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)";
    let passhash = calculate_passhash(account_name.to_owned().as_str(), password);
    let row = db_conn.prep_exec(query, vec![account_name, passhash]).unwrap();
    let last_insert_id = row.last_insert_id();
    let mut d = BTreeMap::new();
    res.clear_jwt();
    d.insert("user_id".to_owned(), last_insert_id.to_json());
    res.set_jwt_user_and_custom_claims("isu", d);
    return res.redirect("/");
}

fn post_comment<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let me = get_session_user(req);
    if !me.is_login() {
        return res.redirect("/login");
    }

    let csrf_token: String;
    let post_id: String;
    let comment: String;
    {
        {
            let form_data = try_with!(res, req.form_body());
            csrf_token = form_data.get("csrf_token").unwrap().to_string();
            post_id = form_data.get("post_id").unwrap().to_string();
            comment = form_data.get("comment").unwrap().to_string();
        }

        let session_csrf_token = {
            match (*req).valid_custom_claims() {
                None => "",
                Some(v) => {
                    match v.get("csrf_token") {
                        None => "",
                        Some(v) => v.as_string().unwrap(),
                    }
                }
            }
        };
        if csrf_token != session_csrf_token {
            println!("{} != {}", csrf_token, session_csrf_token);
            res.set(StatusCode::PreconditionFailed);
            return res.next_middleware();
        }
    }

    let query = "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)";
    let _ = db_conn.prep_exec(query, (post_id.to_owned(), me.id, comment)).unwrap();

    res.redirect(format!("/posts/{}", post_id.to_owned()))
}

fn get_admin_banned<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let csrf_token: String = {
        get_csrf_token(req)
    };
    let me = get_session_user(req);
    if !me.is_login() {
        return res.redirect("/");
    }

    if me.authority == 0 {
        res.set(StatusCode::Forbidden);
        return res.send("");
    }

    let query = "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC";
    let users: Vec<User> = db_conn.prep_exec(query, ())
        .map(|ret| {
            ret.map(|x| x.unwrap())
                .map(|mut row| {
                    let tm = time::at_utc(row.take("created_at").unwrap());
                    let created_at = time::strftime("%Y-%m-%dT%H:%M:%S%z", &tm).unwrap();
                    User {
                        id: from_value(row.take("id").unwrap()),
                        account_name: from_value(row.take("account_name").unwrap()),
                        passhash: from_value(row.take("passhash").unwrap()),
                        authority: from_value(row.take("authority").unwrap()),
                        del_flg: from_value(row.take("del_flg").unwrap()),
                        created_at: created_at,
                    }
                })
                .collect()
        })
        .unwrap();

    let mut ctx = Context::new();
    let notice = "";
    ctx.add("notice", &notice);
    ctx.add("me", &me);
    ctx.add("users", &users);
    ctx.add("csrf_token", &csrf_token);
    res.send(req.template_engine().render("banned.html", ctx).unwrap())
}

fn post_admin_banned<'mw>(req: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let csrf_token: String = {
        get_csrf_token(req)
    };
    let me = get_session_user(req);
    if !me.is_login() {
        return res.redirect("/");
    }

    if me.authority == 0 {
        res.set(StatusCode::Forbidden);
        return res.send("");
    }
 
    {
        let form_data = try_with!(res, req.form_body());
        let form_csrf_token = form_data.get("csrf_token").unwrap().to_string();
        if form_csrf_token != csrf_token {
            res.set(StatusCode::UnprocessableEntity);
            return res.send("");
        }
    }

    let query = "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?";
    let _ = db_conn.prep_exec(query, (1, 999999999));

    res.redirect("/admin/banned")
}

fn get_logout<'mw>(_: &mut Request, mut res: Response<'mw>) -> MiddlewareResult<'mw> {
    res.clear_jwt();
    return res.redirect("/");
}

fn initialize<'mw>(req: &mut Request, res: Response<'mw>) -> MiddlewareResult<'mw> {
    let db_conn = req.db_connection();
    let _ = db_conn.prep_exec("DELETE FROM users WHERE id > 1000", ());
    let _ = db_conn.prep_exec("DELETE FROM posts WHERE id > 10000", ());
    let _ = db_conn.prep_exec("DELETE FROM comments WHERE id > 100000", ());
    let _ = db_conn.prep_exec("UPDATE users SET del_flg = 0", ());
    let _ = db_conn.prep_exec("UPDATE users SET del_flg = 1 WHERE id % 50 = 0", ());
    res.next_middleware()
}

fn main() {
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("hogekey"));
    let mut router = Nickel::router();

    let root_path = env::current_dir().unwrap();
    let template_dir = root_path.join(Path::new("templates/*.html"));
    server.utilize(TeraMiddleware::new(template_dir.to_str().unwrap()));

    let db_password = match env::var("ISUCONP_DB_PASSWORD") {
        Ok(v) => v,
        Err(_) => "".to_string(),
    };
    server.utilize(MysqlMiddleware::new(DB_NAME, DB_USER, db_password.as_str()));
    server.utilize(SessionMiddleware::new("hogehoge"));

    router.get("/initialize", initialize);
    router.get("/", get_index);
    router.post("/", post_index);
    router.get("/login", get_login);
    router.post("/login", post_login);
    router.get("/register", get_register);
    router.post("/register", post_register);
    router.get(Regex::new(r"/image/(?P<id>\w+).(?P<ext>\w+)").unwrap(), get_image);
    router.get("/logout", get_logout);
    router.get(Regex::new(r"/posts/(?P<id>\w+)").unwrap(), get_posts_id);
    router.get(Regex::new(r"/@(?P<name>[a-zA-Z]+)").unwrap(), get_account_name);
    router.post("/comment", post_comment);
    router.get("/admin/banned", get_admin_banned);
    router.post("/admin/banned", post_admin_banned);

    server.utilize(Logger);
    server.utilize(StaticFilesHandler::new("assets/"));
    server.utilize(router);
    let custom_handler: fn(&mut NickelError<()>, &mut Request<()>) -> Action = custom_handler;
    server.handle_error(custom_handler);
    server.listen("127.0.0.1:8080");
}
