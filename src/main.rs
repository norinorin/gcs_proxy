use std::env;
use std::time::Duration;

use actix_web::client::Client;
use actix_web::http::header::{HOST, USER_AGENT};
use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use clap::{value_t, Arg};
use url::Url;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

async fn forward(
    req: HttpRequest,
    body: web::Bytes,
    client: web::Data<Client>,
    bucket: web::Data<String>,
) -> Result<HttpResponse, Error> {
    let mut url = Url::parse("http://storage.googleapis.com").unwrap();
    url.set_path(&format!("/{}{}", bucket.get_ref(), req.uri().path()));
    url.set_query(req.uri().query());

    let res = client
        .request_from(url.as_str(), req.head())
        .no_decompress()
        .header(HOST, url.host().unwrap().to_string())
        .header(
            USER_AGENT,
            format!("GCS Proxy/{}", VERSION.unwrap_or("unknown")),
        )
        .header("router-host", req.connection_info().host())
        .timeout(Duration::from_secs(300))
        .send_body(body)
        .await
        .map_err(Error::from)?;

    let mut client_resp = HttpResponse::build(res.status());
    // Remove `Connection` as per
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.header(header_name.clone(), header_value.clone());
    }

    Ok(client_resp.streaming(res))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    env_logger::init();

    let matches = clap::App::new("GCS Proxy")
        .arg(
            Arg::with_name("listen_addr")
                .takes_value(true)
                .value_name("LISTEN ADDR")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("listen_port")
                .takes_value(true)
                .value_name("LISTEN PORT")
                .index(2)
                .required(true),
        )
        .arg(
            Arg::with_name("bucket")
                .takes_value(true)
                .value_name("BUCKET")
                .index(3)
                .required(true),
        )
        .get_matches();

    let listen_addr = matches.value_of("listen_addr").unwrap();
    let bucket = matches.value_of("bucket").unwrap().to_string();
    let listen_port = value_t!(matches, "listen_port", u16).unwrap_or_else(|e| e.exit());

    HttpServer::new(move || {
        App::new()
            .data(Client::new())
            .data(bucket.clone())
            .wrap(middleware::Logger::default())
            .default_service(web::route().to(forward))
    })
    .bind((listen_addr, listen_port))?
    .system_exit()
    .run()
    .await
}