use std::env;

use actix_session::{CookieSession, Session};
use actix_web::client::{Client, ClientBuilder};
use actix_web::http::header::{HOST, USER_AGENT};
use actix_web::{get, middleware, post, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use clap::Arg;
use cloud_storage::object::{ListRequest, Object};
use dotenv::dotenv;
use futures_util::StreamExt;
use itertools::Itertools;
use url::form_urlencoded::byte_serialize;
use url::Url;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

async fn forward(
    session: Session,
    req: HttpRequest,
    body: web::Bytes,
    client: web::Data<Client>,
    bucket: web::Data<String>,
    auth: web::Data<[String; 2]>,
) -> Result<HttpResponse, Error> {
    let bucket = bucket.get_ref();
    let path = req.uri().path();

    let mut url = Url::parse("http://storage.googleapis.com").unwrap();
    url.set_path(&format!("/{}{}", bucket, path));

    let host = req.connection_info().host().to_string();
    let res = client
        .request_from(url.as_str(), req.head())
        .no_decompress()
        .header(HOST, url.host().unwrap().to_string())
        .header(
            USER_AGENT,
            format!("GCS Proxy/{}", VERSION.unwrap_or("unknown")),
        )
        .header("x-forwarded-host", host.clone())
        .send_body(body)
        .await
        .map_err(Error::from)?;

    let status = res.status();

    if [403, 404].contains(&status.as_u16()) {
        return Ok(list_files(
            host,
            bucket,
            path.trim_start_matches('/').to_string(),
            session,
            auth.get_ref(),
        ));
    }

    let mut client_resp = HttpResponse::build(status);
    // Remove `Connection` as per
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.header(header_name.clone(), header_value.clone());
    }

    Ok(client_resp.streaming(res))
}

#[get("/login")]
async fn login_get() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/login.html")))
}

#[post("/login")]
async fn login_post(
    session: Session,
    mut body: web::Payload,
    auth: web::Data<[String; 2]>,
) -> Result<&'static str, Error> {
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item?);
    }

    let auth = auth
        .get_ref()
        .iter()
        .map(|s| byte_serialize(s.as_bytes()).collect::<String>())
        .collect::<Vec<String>>();

    let (username, password) = auth.iter().next_tuple().unwrap();
    let real_auth = format!("login={}&password={}", username, password);
    let bytes = bytes.to_vec();
    let input = std::str::from_utf8(&bytes).unwrap_or("");

    if real_auth != input {
        return Ok("Credentials don't match!");
    }

    session.set("username", username)?;
    session.set("password", password)?;

    Ok("Successfully authorized!")
}

#[get("/logout")]
async fn logout(session: Session) -> Result<&'static str, Error> {
    session.clear();
    Ok("Session has been cleared!")
}

fn sizeof_fmt(mut num: u64, suffix: Option<&str>) -> String {
    let suffix = suffix.unwrap_or("B");
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"].iter() {
        if num < 1024 {
            return format!("{:3}{}{}", num, unit, suffix);
        }
        num /= 1024;
    }

    return format!("{:.1}{}{}", num, "Yi", suffix);
}

// Still finding a way on how to run this in tokio v1.x reactor
// since apparently actix-web runs in tokio v0.2.
// So in the meantime, I'll keep this synchronous.
// Or I missed something, slap me with PRs T_T.
fn list_files(
    host: String,
    bucket: &String,
    path: String,
    session: Session,
    auth: &[String; 2],
) -> HttpResponse {
    let username = session
        .get::<String>("username")
        .unwrap_or(None)
        .unwrap_or("".to_string());
    let password = session
        .get::<String>("password")
        .unwrap_or(None)
        .unwrap_or("".to_string());

    if username != auth[0] || password != auth[1] {
        return HttpResponse::Forbidden()
            .content_type("text/plain")
            .body("Unauthorized!");
    }

    let delimiter = if path.is_empty() {
        Some("/".to_string())
    } else {
        None
    };

    let objects = match Object::list_sync(
        bucket,
        ListRequest {
            delimiter,
            prefix: Some(path.clone()),
            ..Default::default()
        },
    ) {
        Ok(objects) => objects,
        Err(_e) => {
            return HttpResponse::InternalServerError()
                .content_type("text/plain")
                .body("Internal server error occurred");
        }
    };

    // this is a bit yikes, but whatever
    let table = format!(
        r#"
        <style>
            table, td {{
                border: 0;
            }}
        </style>
        <table>
            <tr></td><a href="http://{}">/</a></td></tr>
        "#,
        host
    );
    let mut files = vec![];
    let mut prefixes = vec![];
    for object in objects {
        for item in object.items {
            files.push(format!(
                r#"<tr>
                <td><a href="http://{0}/{1}">{1}</a></td>
                <td>{2}</td>
                <td style="float: right;">{3}</td>
                </tr>"#,
                host,
                item.name,
                item.time_created,
                sizeof_fmt(item.size, None)
            ))
        }
        for prefix in object.prefixes.iter().filter(|p| *p != "/" && *p != &path) {
            prefixes.push(format!(
                r#"<tr><td><a href="http://{0}/{1}">{1}</a></td></tr>"#,
                host, prefix
            ))
        }
    }

    if files.is_empty() && prefixes.is_empty() {
        return HttpResponse::NotFound()
            .content_type("text/plain")
            .body("404");
    }

    files.sort();
    prefixes.sort();

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            r#"
            Path: {}<br>
            {}{}{}</table>
            "#, // Tell me a better way to do this thanks
            path,
            table,
            prefixes.join(""),
            files.join("")
        ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let username = env::var("AUTH_USERNAME").expect("Missing AUTH_USERNAME variable");
    let password = env::var("AUTH_PASSWORD").expect("Missing AUTH_PASSWORD variable");

    env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    env::set_var("SERVICE_ACCOUNT", "auth.json");
    env_logger::init();

    let matches = clap::App::new("GCS Proxy")
        .arg(
            Arg::with_name("listen_addr")
                .takes_value(true)
                .value_name("LISTEN ADDR:PORT")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("bucket")
                .takes_value(true)
                .value_name("BUCKET")
                .index(2)
                .required(true),
        )
        .get_matches();

    let listen_addr = matches.value_of("listen_addr").unwrap().to_string();
    let bucket = matches.value_of("bucket").unwrap().to_string();

    HttpServer::new(move || {
        App::new()
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .data(ClientBuilder::new().disable_timeout().finish())
            .data(bucket.clone())
            .data([username.clone(), password.clone()])
            .wrap(middleware::Logger::default())
            .service(login_get)
            .service(login_post)
            .service(logout)
            .default_service(web::route().to(forward))
    })
    .bind(listen_addr)?
    .run()
    .await
}
