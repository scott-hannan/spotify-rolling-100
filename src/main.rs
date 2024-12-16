mod auth;
mod landing;

use actix_web::{web, App, HttpServer};

use reqwest::Client;
use std::sync::Arc;

use crate::auth::{login, callback};
use crate::landing::index;


/// Auth to Spotify w/ PKCE https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Create a thread-safe reqwest client
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    
    let client = Arc::new(Client::new());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone())) // Share the reqwest client
            .route("/", web::get().to(index))       
            .route("/login", web::get().to(login))    
            .route("/callback", web::get().to(callback)) 
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}