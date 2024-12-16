use actix_web::{HttpResponse, Responder};

pub async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<h1>Welcome to My App</h1><p>This is the landing page.</p>")
}