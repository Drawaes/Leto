using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Leto.Tls13.Hash;

namespace Leto.Tls13.Certificates.Windows
{
    public class RsaCertificate : ICertificate
    {
        private byte[][] _certificateChain;
        private X509Certificate2 _certificate;
        private System.Security.Cryptography.RSA _privateKey;

        public RsaCertificate(X509Certificate2 certificate, X509Certificate2Collection chain)
        {
            _certificate = certificate;
            _privateKey = _certificate.GetRSAPrivateKey();
            _certificateChain = new byte[chain.Count][];
            for(var i = 0; i < chain.Count;i++)
            {
                _certificateChain[i] = chain[i].RawData;
            }
        }

        public byte[][] CertificateChain => _certificateChain;
        public byte[] CertificateData => _certificate.RawData;
        public CertificateType CertificateType => CertificateType.Rsa;

        public string HostName
        {
            get
            {
                throw new NotImplementedException();
            }
        }
        
        public int SignatureSize(SignatureScheme scheme)
        {
            return _privateKey.KeySize;
        }

        public unsafe int SignHash(IHashProvider provider, SignatureScheme scheme, ref WritableBuffer writer, byte* message, int messageLength)
        {
            throw new NotImplementedException();
        }

        public bool SupportsSignatureScheme(SignatureScheme scheme)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
