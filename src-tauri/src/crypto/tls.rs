//! TLS profiles for qorc-controlled transports.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

#[derive(Debug)]
struct OnionCertificateVerifier {
    supported_schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for OnionCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_schemes.clone()
    }
}

pub fn strict_post_quantum_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider
}

pub fn controlled_client_config(onion_service: bool) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(strict_post_quantum_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS 1.3 is unavailable".to_string())?;

    let mut config = if onion_service {
        let supported_schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(OnionCertificateVerifier {
                supported_schemes,
            }))
            .with_no_client_auth()
    } else {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (accepted, _) = roots.add_parsable_certificates(native.certs);
        if accepted == 0 {
            return Err("No native TLS trust roots are available".to_string());
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::strict_post_quantum_provider;
    use rustls::NamedGroup;

    #[test]
    fn controlled_tls_has_no_classical_key_exchange_fallback() {
        let provider = strict_post_quantum_provider();
        let groups: Vec<_> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert_eq!(groups, vec![NamedGroup::X25519MLKEM768]);
    }
}
