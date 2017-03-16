using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Leto.Certificates
{
    public class ManagedCertificate:ICertificate
    {
        private RSA _rsaPrivateKey;
        private ECDsa _ecdsaPrivateKey;
        private CertificateType _certificateType;
        private byte[] _certificateData;

        public ManagedCertificate(X509Certificate2 certificate, X509Certificate2Collection chain)
        {
            _rsaPrivateKey = certificate.GetRSAPrivateKey();
            if(_rsaPrivateKey != null)
            {
                _certificateType = CertificateType.rsa;
                _certificateData = certificate.RawData;
                return;
            }
            _ecdsaPrivateKey = certificate.GetECDsaPrivateKey();
            if(_ecdsaPrivateKey != null)
            {
                _certificateType = CertificateType.ecdsa;
                _certificateData = certificate.RawData;
            }
            throw new CryptographicException("Unable to get a private key from the certificate");
        }

        public CertificateType CertificateType => _certificateType;
    }
}
