#[macro_use]
extern crate log;
extern crate env_logger;
extern crate afterparty_ng;
extern crate hyper;

use afterparty_ng::{Delivery, Hub};

use hyper::Server;

pub fn main() {
    env_logger::init();
    let addr = format!("0.0.0.0:{}", 4567);
    let mut hub = Hub::new();
    hub.handle("pull_request", |delivery: &Delivery| {
        info!("rec delivery {:#?}", delivery);
        /*match delivery.payload {
            Event::PullRequest { ref action, ref sender, .. } => {
                info!("sender {} action {}", sender.login, action)
            }
            _ => (),
        }*/
    });
    let srvc = Server::http(&addr[..])
                   .unwrap()
                   .handle(hub);
    info!("listening on {}", addr);
    srvc.unwrap();
}
