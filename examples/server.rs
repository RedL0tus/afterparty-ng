#[macro_use]
extern crate log;
extern crate afterparty_ng;
extern crate env_logger;
extern crate futures;
extern crate hyper;

use afterparty_ng::{Delivery, Hub};
use futures::Future;
use std::env;

use hyper::Server;

pub fn main() {
    if let Err(_) = env::var("AFTERPARTY_LOG") {
        env::set_var("AFTERPARTY_LOG", "info")
    }
    env_logger::init_from_env("AFTERPARTY_LOG");
    let addr = format!("0.0.0.0:{}", 4567);
    let mut hub = Hub::new();
    hub.handle("star", |delivery: &Delivery| {
        info!("Received delivery {:#?}", delivery);
        /*match delivery.payload {
            Event::PullRequest { ref action, ref sender, .. } => {
                info!("sender {} action {}", sender.login, action)
            }
            _ => (),
        }*/
    });
    let server = Server::bind(&addr[..].parse().unwrap())
        .serve(hub)
        .map_err(|e| error!("Server error: {}", e));
    info!("listening on {}", addr);
    hyper::rt::run(server);
}
