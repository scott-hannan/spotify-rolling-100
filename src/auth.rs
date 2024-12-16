use std::env;
use once_cell::sync::Lazy;
use reqwest::Client;
use actix_web::{web, HttpResponse, Responder};
use std::sync::Arc;
use rand::{distributions::Alphanumeric, Rng};
use url::form_urlencoded::Serializer;
use serde::{Deserialize, Serialize};


static CLIENT_ID: Lazy<String> = Lazy::new(|| {
    env::var("CLIENT_ID").expect("CLIENT_ID must be set")
});
static CLIENT_SECRET: Lazy<String> = Lazy::new(|| {
    env::var("CLIENT_SECRET").expect("CLIENT_SECRET must be set")
});
const REDIRECT_URI: &str = "http://127.0.0.1:8000/callback";
const SCOPE: &str = "user-read-private user-read-email";

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>, 
    state: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
}

pub async fn callback(query: web::Query<CallbackQuery>, client: web::Data<Client>) -> impl Responder {
    let code = &query.code.as_deref().expect("Expected a code");;
    let state = &query.state;

    if state.is_none() {
        let redirect_url = format!(
            "/#{}",
            Serializer::new(String::new())
                .append_pair("error", "state_mismatch")
                .finish()
        );
        return HttpResponse::Found()
            .append_header(("Location", redirect_url))
            .finish();
    }


    let token_url = "https://accounts.spotify.com/api/token";
    let token_form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID.as_str()), 
        ("client_secret", CLIENT_SECRET.as_str()),
    ];

     // Send POST request to Spotify to exchange authorization code for access token
     let response = client
     .post(token_url)
     .form(&token_form)
     .send()
     .await;

     match response {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<TokenResponse>().await {
                    Ok(token_response) => HttpResponse::Ok().json(token_response),
                    Err(_) => HttpResponse::InternalServerError()
                        .body("Failed to parse token response from Spotify"),
                }
            } else {
                HttpResponse::InternalServerError()
                    .body("Failed to exchange authorization code for token")
            }
        }
        Err(_) => HttpResponse::InternalServerError()
            .body("Error connecting to Spotify's token endpoint"),
    }

}

pub async fn login() -> impl Responder {
    let state: String = rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(16)
    .map(char::from)
    .collect();

    let auth_url = format!(
        "https://accounts.spotify.com/authorize?{}",
        Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", CLIENT_ID.as_str())
            .append_pair("scope", SCOPE)
            .append_pair("redirect_uri", REDIRECT_URI)
            .append_pair("state", &state)
            .finish()
    );

    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()

}
