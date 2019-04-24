//! Afterparty is a github webhook handler library for building custom integrations

#[macro_use]
extern crate log;
extern crate case;
extern crate futures;
extern crate hex;
extern crate hyper;
extern crate ring;

extern crate serde;
extern crate serde_json;

mod events;
mod hook;

pub use events::Event;
pub use hook::{AuthenticateHook, Hook};

use futures::stream::Stream;
use futures::{future, Future};
use hyper::service::{NewService, Service};
use hyper::{Body, Error, Request, Response, StatusCode};

use std::collections::HashMap;

/// Get value of the the header in hyper 0.12
macro_rules! get_header_value {
    ($headers:expr, $key:expr) => {
        if let Some(value) = $headers.get($key) {
            if let Ok(inner) = value.to_str() {
                Some(inner.clone())
            } else {
                None
            }
        } else {
            None
        }
    };
}

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

pub struct Worker {
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
        H: Hook + Clone + 'static,
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

impl Worker {
    /// get all interested hooks for a given event
    pub fn hooks(&self, event: &str) -> Option<Vec<&Box<Hook>>> {
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

    fn response(
        scode: StatusCode,
        resbody: &'static str,
    ) -> Box<Future<Item = Response<Body>, Error = Error> + Send> {
        Box::new(future::ok(
            Response::builder()
                .status(scode)
                .body(resbody.into())
                .unwrap(),
        ))
    }
}

impl From<&Hub> for Worker {
    fn from(hub: &Hub) -> Self {
        Self {
            hooks: hub.hooks.clone(),
        }
    }
}

impl Service for Worker {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<Future<Item = Response<Body>, Error = Error> + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        let headers = req.headers().clone();

        // Name of Github event and unique ID for each delivery.
        // See [this document](https://developer.github.com/webhooks/#events) for available types
        let event = get_header_value!(&headers, "X-Github-Event");
        let delivery = get_header_value!(&headers, "X-Github-Delivery");
        if event.is_none() || delivery.is_none() {
            return Worker::response(StatusCode::ACCEPTED, "Invalid request");
        }
        let event_str = event.unwrap();
        let delivery_str = delivery.unwrap();

        info!("Received '{}' event with ID {}", &event_str, &delivery_str);

        // signature for request
        // see [this document](https://developer.github.com/webhooks/securing/) for more information
        let signature = get_header_value!(&headers, "X-Hub-Signature");
        let hooks = self.hooks(&event_str);
        if hooks.is_none() {
            error!("No matched hook found");
            return Worker::response(StatusCode::ACCEPTED, "No matched hook found");
        }
        let hooks = hooks.unwrap();
        debug!("{} hook(s) found", hooks.len());
        info!("Wait ");
        let payload = if let Ok(payload_string) = req
            .into_body()
            .concat2()
            .map(|chunk| String::from_utf8_lossy(&chunk.to_vec()).to_string())
            .wait()
        {
            payload_string
        } else {
            error!("Unable to receive payload body");
            return Worker::response(StatusCode::ACCEPTED, "Invalid request");
        };
        let payload_str = payload.as_str();
        debug!("Request body: {}", &payload_str);
        if let Some(delivery) = Delivery::new(&delivery_str, &event_str, payload_str, signature) {
            for hook in hooks {
                hook.handle(&delivery);
            }
        }
        debug!("Finished");
        return Worker::response(StatusCode::OK, "OK");
    }
}

impl NewService for Hub {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Service = Worker;
    type Future = Box<Future<Item = Self::Service, Error = Self::InitError> + Send>;
    type InitError = Error;

    fn new_service(&self) -> Self::Future {
        Box::new(future::ok(Worker::from(self)))
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
        assert_eq!(2, hub.len())
    }
}
