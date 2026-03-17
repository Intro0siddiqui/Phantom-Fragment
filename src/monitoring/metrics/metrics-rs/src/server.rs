use super::MetricsCollector;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use std::sync::Arc;

pub struct MetricsServer {
    collector: Arc<MetricsCollector>,
}

impl MetricsServer {
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    pub async fn run(&self, bind_addr: &str) -> std::io::Result<()> {
        let collector = self.collector.clone();

        log::info!("Starting metrics server on {}", bind_addr);

        HttpServer::new(move || {
            let collector = collector.clone();
            App::new()
                .app_data(web::Data::new(collector))
                .route("/metrics", web::get().to(metrics_handler))
        })
        .bind(bind_addr)?
        .run()
        .await
    }
}

async fn metrics_handler(collector: web::Data<Arc<MetricsCollector>>) -> impl Responder {
    match collector.export() {
        Ok(metrics) => HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4")
            .body(metrics),
        Err(e) => {
            log::error!("Failed to export metrics: {:?}", e);
            HttpResponse::InternalServerError().body("Internal Server Error")
        }
    }
}
