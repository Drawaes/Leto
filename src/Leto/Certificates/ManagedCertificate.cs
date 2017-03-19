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
        private byte[][] _certificateChain;

        public ManagedCertificate(X509Certificate2 certificate, X509Certificate2Collection chain)
        {
            if (chain == null || chain.Count == 0)
            {
                _certificateChain = new byte[0][];
            }
            else
            {
                _certificateChain = new byte[chain.Count][];
                for(int i = 0; i < _certificateChain.Length;i++)
                {
                    _certificateChain[i] = chain[i].RawData;
                }
            }
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
                return;
            }
            throw new CryptographicException("Unable to get a private key from the certificate");
        }

        public CertificateType CertificateType => _certificateType;
        public byte[] CertificateData => _certificateData;
        public byte[][] CertificateChain => _certificateChain;
    }
}
