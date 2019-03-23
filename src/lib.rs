#![feature(clone_closures)]

//! Afterparty is a github webhook handler library for building custom integrations

#[macro_use]
extern crate log;
extern crate hyper;
extern crate case;
extern crate hex;
extern crate ring;
extern crate futures;

extern crate serde;
extern crate serde_json;

mod events;
mod hook;

pub use events::Event;
pub use hook::{AuthenticateHook, Hook};

use futures::{future, Future};
use futures::stream::Stream;
use hyper::service::{Service, NewService};
use hyper::{Body, Error, Response, StatusCode, Request};

use std::collections::HashMap;

// A delivery encodes all information about web hook request
#[derive(Debug)]
pub struct Delivery<'a> {
    pub id: &'a str,
    pub event: &'a str,
    pub payload: Event,
    pub unparsed_payload: &'a str,
    pub signature: Option<&'a str>,
}

impl<'a> Delivery<'a> {
    pub fn new(
        id: &'a str,
        event: &'a str,
        payload: &'a str,
        signature: Option<&'a str>,
    ) -> Option<Delivery<'a>> {
        // patching raw payload with camelized name field for enum deserialization
        let patched = events::patch_payload_json(event, payload);
        match serde_json::from_str::<Event>(&patched) {
            Ok(parsed) => Some(Delivery {
                id,
                event,
                payload: parsed,
                unparsed_payload: payload,
                signature,
            }),
            Err(e) => {
                // println!("{}", e);
                // println!("failed to parse json {:?}\n{:#?}", e, patched);
                error!("failed to parse json {:?}\n{:#?}", e, patched);
                None
            }
        }
    }
}

/// A hub is a registry of hooks
#[derive(Default)]
pub struct Hub {
    hooks: HashMap<String, Vec<Box<Hook>>>,
}

impl Hub {
    /// construct a new hub instance
    pub fn new() -> Hub {
        Hub {
            ..Default::default()
        }
    }

    /// adds a new web hook which will only be applied
    /// when a delivery is received with a valid
    /// request signature based on the provided secret
    pub fn handle_authenticated<H, S>(&mut self, event: &str, secret: S, hook: H)
    where
        H: Hook + 'static,
        S: Into<String>,
    {
        self.handle(event, AuthenticateHook::new(secret, hook))
    }

    /// add a need hook to list of hooks
    /// interested in a given event
    pub fn handle<H>(&mut self, event: &str, hook: H)
    where
        H: Hook + 'static,
    {
        self.hooks
            .entry(event.to_owned())
            .or_insert(vec![])
            .push(Box::new(hook));
    }

    pub fn len(&self) -> usize {
        self.hooks.len()
    }
}

pub struct Worker<'a> {
    hooks: &'a HashMap<String, Vec<Box<Hook>>>
}

impl<'a> Worker<'a> {
    fn from(hooks: &HashMap<String, Vec<Box<Hook>>>) -> Worker {
        Worker {
            hooks
        }
    }

    /// get all interested hooks for a given event
    fn hooks(&self, event: &str) -> Option<Vec<&Box<Hook>>> {
        debug!("Finding matches for '{}'", event);
        let explicit = self.hooks.get(event);
        let implicit = self.hooks.get("*");
        let combined = match (explicit, implicit) {
            (Some(ex), Some(im)) => {
                Some(ex.iter().chain(im.iter()).into_iter().collect::<Vec<_>>())
            }
            (Some(ex), _) => Some(ex.into_iter().collect::<Vec<_>>()),
            (_, Some(im)) => Some(im.into_iter().collect::<Vec<_>>()),
            _ => None,
        };
        combined
    }

    fn response(scode: StatusCode, resbody: &'static str) -> Box<Future<Item = Response<Body>, Error = Error> + Send> {
        Box::new(
            future::ok(
                Response::builder()
                    .status(scode)
                    .body(resbody.into())
                    .unwrap()
            )
        )
    }
}

impl<'a> Service for Worker<'a> {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<Future<Item = Response<Body>, Error = Error> + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        let headers = req.headers().clone();
        // Name of Github event and unique ID for each delivery.
        // See [this document](https://developer.github.com/webhooks/#events) for available types
        let (event_str, delivery_str) = if let (Some(event), Some(delivery)) = (
            headers.get("X-GitHub-Event"), headers.get("X-Github-Delivery")) {
            if let (Ok(event_str), Ok(delivery_str)) = (event.to_str(), delivery.to_str()) {
                (event_str, delivery_str)
            } else {
                error!("Invalid headers");
                return Worker::response(StatusCode::BAD_REQUEST, "Invalid headers")
            }
        } else {
            error!("Invalid request");
            return Worker::response(StatusCode::BAD_REQUEST, "Invalid Response")
        };
        // signature for request
        // see [this document](https://developer.github.com/webhooks/securing/) for more information
        let signature = if let Some(value) = headers.get("X-Hub-Signature") {
            value.to_str().ok()
        } else {
            None
        };
        info!("Received '{}' event with ID {}", &event_str, &delivery_str);
        if let Some(hooks) = self.hooks(&event_str) {
            let body = if let Ok(chunk) = req.into_body().concat2().wait() {
                chunk
            } else {
                error!("Failed to retrieve request body");
                return Worker::response(StatusCode::BAD_REQUEST, "Failed to retrieve request body")
            };
            if let Ok(payload) = String::from_utf8(body.to_vec()) {
                if let Some(delivery) = Delivery::new(&delivery_str,
                                                      &event_str,
                                                      &payload.as_str(),
                                                      signature) {
                    for hook in hooks {
                        hook.handle(&delivery);
                    }
                    Worker::response(StatusCode::ACCEPTED, "OK")
                } else {
                    error!(
                        "Failed to parse event {:?} for delivery {:?}",
                        &event_str, &delivery_str
                    );
                    Worker::response(StatusCode::BAD_REQUEST, "Failed to parse event")
                }
            } else {
                error!("Failed to parse request body");
                Worker::response(StatusCode::BAD_REQUEST, "Failed to parse request body")
            }
        } else {
            error!("No proper hook found");
            Worker::response(StatusCode::INTERNAL_SERVER_ERROR, "Server not configured")
        }
    }
}

impl<'a> NewService for Hub {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Service = Worker<'a>;
    type Future = Box<Future<Item = Self::Service, Error = Self::InitError> + Send>;
    type InitError = Error;

    fn new_service(&self) -> Self::Future {
        Box::new(future::ok(Worker::from(&self.hooks)))
    }
}

#[cfg(test)]
mod tests {
    use super::{Delivery, Hub};

    #[test]
    fn hub_hooks() {
        let mut hub = Hub::new();
        // UFCS may be required is hyper::server::Handler is in scope
        // Hub::handle(&mut hub, "push", |_: &Delivery| {});
        // Hub::handle(&mut hub, "*", |_: &Delivery| {});
        hub.handle("push", |_: &Delivery| {});
        hub.handle("*", |_: &Delivery| {});
        assert_eq!(
            Some(2),
            hub.len()
        )
    }
}
