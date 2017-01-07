using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using static Interop.LibCrypto;

namespace Leto.Tls13.Certificates.OpenSsl11
{
    public class EcdsaCertificate : ICertificate
    {
        private EVP_PKEY _key;
        private X509 _certificate;
        private string _curveName;
        private byte[] _certData;
        private string _altNameString;
        private SignatureScheme _scheme;

        internal EcdsaCertificate(EVP_PKEY privateKey, X509 certificate, byte[] derCertData, string altNameString)
        {
            _certData = derCertData;
            _key = privateKey;
            _certificate = certificate;
            _altNameString = altNameString;

            var key = EVP_PKEY_get0_EC_KEY(_key);
            var group = EC_KEY_get0_group(key);
            var curveName = EC_GROUP_get_curve_name(group);
            _curveName = OBJ_nid2ln(curveName);
            switch(_curveName)
            {
                case "secp256r1":
                    _scheme = SignatureScheme.ecdsa_secp256r1_sha256;
                    break;
                case "secp384r1":
                    _scheme = SignatureScheme.ecdsa_secp384r1_sha384;
                    break;
                case "secp521r1":
                    _scheme = SignatureScheme.ecdsa_secp521r1_sha512;
                    break;
                default:
                    ExceptionHelper.ThrowException(new ArgumentException());
                    break;
            }
        }

        public bool SupportsSignatureScheme(SignatureScheme scheme)
        {
            return scheme == _scheme;
        }

        public CertificateType CertificateType => CertificateType.Ecdsa_secp256r1;
        public byte[] CertificateData => _certData;
        public string HostName => _altNameString;

        public void Dispose()
        {
            _key.Free();
            _certificate.Free();
            GC.SuppressFinalize(this);
        }
        ~EcdsaCertificate()
        {
            Dispose();
        }
    }
}
