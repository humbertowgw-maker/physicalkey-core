import Foundation
import CryptoKit

/// Pins the backend's TLS chain to Let's Encrypt's issuing intermediate ("YE1") rather than
/// the leaf certificate. Railway serves this app behind a shared wildcard cert
/// (`*.up.railway.app`) that Railway rotates on its own schedule, entirely outside this
/// project's control; pinning to that leaf key would break the app the next time Railway
/// rotates it, with no recovery short of an App Store update. Pinning to the issuing
/// intermediate instead survives any normal leaf rotation while still rejecting a
/// connection signed by a completely different CA (the actual MITM scenario this defends
/// against) — the standard practical tradeoff point (see OWASP/Apple's own pinning
/// guidance): more stable than the leaf, without the correctness trap described below.
///
/// Deliberately NOT pinned to the true root (ISRG Root X1) or the outermost cross-sign cert
/// the server transmits ("ISRG Root X2") — a real, non-obvious failure mode was found and
/// reproduced while building this: macOS/iOS's Security framework substitutes its OWN
/// locally-trusted copy of whichever certificate in the chain is closest to a local trust
/// anchor, rather than surfacing exactly what the server transmitted, for that outermost
/// position. Confirmed empirically: comparing raw `openssl s_client -showcerts` output
/// against what `SecTrustCopyCertificateChain` actually returns at runtime for a real
/// connection, the leaf and this intermediate hashed identically in both — but the
/// outermost "ISRG Root X2" position did not. Pinning there would be unpredictable, not
/// just less stable. The intermediate one level in is the outermost point confirmed to be
/// exactly what's on the wire, not a local substitution.
///
/// Pins the full certificate (not just its public key) rather than reconstructing a
/// SubjectPublicKeyInfo DER header by hand from key type/size — avoids hand-rolled ASN.1
/// reconstruction entirely (a real correctness risk for something security-critical). This
/// does mean the pin needs updating whenever Let's Encrypt rotates this intermediate
/// (historically on the order of every 1-3 years, not something this project controls the
/// timing of) — a known, accepted tradeoff of intermediate-level pinning, not an oversight.
///
/// Pin verified two ways before shipping: (1) `openssl s_client -showcerts` against the
/// real production backend, `openssl x509 -outform DER | openssl dgst -sha256 -binary |
/// base64` on the intermediate; (2) a real held-out Swift integration test running this
/// exact delegate class against both the real backend (accepted) and an unrelated site on a
/// different CA, google.com (rejected).
final class PinnedURLSessionDelegate: NSObject, URLSessionDelegate {
    private static let pinnedIntermediateCertificateHash = "ojctBkMelxY2Xu7UfsAgNRSX0YL8wDjkV+WBaKA8rAc="

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // Let the system do its normal chain-of-trust validation first (expiry, hostname,
        // revocation, etc.) — pinning only adds a further constraint on top of that, it
        // never replaces it.
        guard SecTrustEvaluateWithError(serverTrust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard anyCertificateInChainMatchesPin(serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }

    /// Checks every certificate in the chain rather than assuming a fixed index — the
    /// pinned intermediate could in principle appear at a different position depending on
    /// how many hops a given handshake includes, and this is robust to that regardless.
    private func anyCertificateInChainMatchesPin(_ serverTrust: SecTrust) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] else {
            return false
        }
        for certificate in chain {
            let der = SecCertificateCopyData(certificate) as Data
            let hash = Data(SHA256.hash(data: der)).base64EncodedString()
            if hash == Self.pinnedIntermediateCertificateHash {
                return true
            }
        }
        return false
    }
}
