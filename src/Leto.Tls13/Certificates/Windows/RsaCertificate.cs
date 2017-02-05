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
        public CertificateType CertificateType => CertificateType.rsa;

        public string HostName
        {
            get
            {
                throw new NotImplementedException();
            }
        }
        
        public int SignatureSize(SignatureScheme scheme)
        {
            return _privateKey.KeySize / 8;
        }

        public unsafe int SignHash(IHashProvider provider, SignatureScheme scheme, ref WritableBuffer writer, byte* message, int messageLength)
        {
            var span = new Span<byte>(message, messageLength);
            var result = _privateKey.SignData(span.ToArray(), GetHashName(scheme), GetPaddingMode(scheme));
            writer.Write(result);
            return result.Length;
        }

        private System.Security.Cryptography.RSASignaturePadding GetPaddingMode(SignatureScheme scheme)
        {
            switch(scheme)
            {
                case SignatureScheme.rsa_pkcs1_sha256:
                case SignatureScheme.rsa_pkcs1_sha384:
                case SignatureScheme.rsa_pkcs1_sha512:
                    return System.Security.Cryptography.RSASignaturePadding.Pkcs1;
                case SignatureScheme.rsa_pss_sha256:
                case SignatureScheme.rsa_pss_sha384:
                case SignatureScheme.rsa_pss_sha512:
                    return System.Security.Cryptography.RSASignaturePadding.Pss;
                default:
                    throw new NotImplementedException();
            }
        }

        private System.Security.Cryptography.HashAlgorithmName GetHashName(SignatureScheme scheme)
        {
            switch(scheme)
            {
                case SignatureScheme.rsa_pkcs1_sha256:
                case SignatureScheme.rsa_pss_sha256:
                    return System.Security.Cryptography.HashAlgorithmName.SHA256;
                case SignatureScheme.rsa_pkcs1_sha384:
                case SignatureScheme.rsa_pss_sha384:
                    return System.Security.Cryptography.HashAlgorithmName.SHA384;
                case SignatureScheme.rsa_pkcs1_sha512:
                case SignatureScheme.rsa_pss_sha512:
                    return System.Security.Cryptography.HashAlgorithmName.SHA512;
            }
            throw new InvalidOperationException();
        }

        public bool SupportsSignatureScheme(SignatureScheme scheme)
        {
            switch(scheme)
            {
                case SignatureScheme.rsa_pkcs1_sha256:
                case SignatureScheme.rsa_pkcs1_sha384:
                case SignatureScheme.rsa_pkcs1_sha512:
                    return true;
            }
            return false;
        }

        public void Dispose()
        {
        }
    }
}
