use super::Delivery;
use hex::FromHex;
use ring::digest;
use ring::hmac;

/// Handles webhook deliveries
pub trait Hook: Send + Sync {
    /// Implementations are expected to deliveries here
    fn handle(&self, delivery: &Delivery);
}

/// A delivery authenticator for hooks
pub struct AuthenticateHook<H: Hook + 'static> {
    secret: String,
    hook: H,
}

impl<H: Hook + 'static> AuthenticateHook<H> {
    pub fn new<S>(secret: S, hook: H) -> AuthenticateHook<H>
    where
        S: Into<String>,
    {
        AuthenticateHook {
            secret: secret.into(),
            hook: hook,
        }
    }

    fn authenticate(&self, payload: &str, signature: &str) -> bool {
        // https://developer.github.com/webhooks/securing/#validating-payloads-from-github
        let sans_prefix = signature[5..signature.len()].as_bytes();
        match Vec::from_hex(sans_prefix) {
            Ok(sigbytes) => {
                let sbytes = self.secret.as_bytes();
                let pbytes = payload.as_bytes();
                let key = hmac::SigningKey::new(&digest::SHA1, &sbytes);
                hmac::verify_with_own_key(&key, &pbytes, &sigbytes).is_ok()
            }
            Err(_) => false,
        }
    }
}

impl<H: Hook + 'static> Hook for AuthenticateHook<H> {
    fn handle(&self, delivery: &Delivery) {
        if let Some(sig) = delivery.signature {
            if self.authenticate(delivery.unparsed_payload, sig) {
                self.hook.handle(delivery)
            } else {
                error!("failed to authenticate request");
            }
        }
    }
}

impl<F> Hook for F
where
    F: Fn(&Delivery),
    F: Sync + Send,
{
    fn handle(&self, delivery: &Delivery) {
        self(delivery)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Delivery;
    use super::*;
    use hex::ToHex;
    use ring::digest;
    use ring::hmac;

    #[test]
    fn authenticate_signatures() {
        let authenticated = AuthenticateHook::new("secret", |_: &Delivery| {});
        let payload = r#"{"zen": "Approachable is better than simple."}"#;
        let secret = "secret";
        let sbytes = secret.as_bytes();
        let pbytes = payload.as_bytes();
        let key = hmac::SigningKey::new(&digest::SHA1, &sbytes);
        let mut signature = String::new();
        hmac::sign(&key, &pbytes)
            .as_ref()
            .write_hex(&mut signature)
            .unwrap();
        assert!(authenticated.authenticate(payload, format!("sha1={}", signature).as_ref()))
    }
}
