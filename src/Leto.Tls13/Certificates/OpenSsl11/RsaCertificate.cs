using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
using static Interop.LibCrypto;

namespace Leto.Tls13.Certificates.OpenSsl11
{
    public class RsaCertificate : ICertificate
    {
        private EVP_PKEY _key;
        private X509 _certificate;
        private byte[] _derCertData;
        private string _altNameString;

        internal RsaCertificate(EVP_PKEY privateKey, X509 certificate, byte[] derCertData, string altNameString)
        {
            _key = privateKey;
            _altNameString = altNameString;
            _derCertData = derCertData;
        }

        public CertificateType CertificateType => CertificateType.Rsa;
        public byte[] CertificateData => _derCertData;
        public string HostName => _altNameString;
        
        public void Dispose()
        {
            _key.Free();
            _certificate.Free();
            GC.SuppressFinalize(this);
        }

        public bool SupportsSignatureScheme(SignatureScheme scheme)
        {
            switch(scheme)
            {
                case SignatureScheme.rsa_pss_sha256:
                case SignatureScheme.rsa_pss_sha384:
                case SignatureScheme.rsa_pss_sha512:
                    return true;
                default:
                    return false;
            }
        }

        public int SignatureSize(SignatureScheme scheme)
        {
            throw new NotImplementedException();
        }

        public unsafe Span<byte> SignHash(IHashProvider provider, SignatureScheme scheme, byte* message, int messageLength)
        {
            throw new NotImplementedException();
        }

        ~RsaCertificate()
        {
            Dispose();
        }
    }
}
