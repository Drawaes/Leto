using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;

namespace Leto.Tls13.Certificates.Windows
{
    public class EcdsaCertificate : ICertificate
    {
        private byte[][] _certificateChain;
        private X509Certificate2 _certificate;
        private System.Security.Cryptography.ECDsa _privateKey;
        private SignatureScheme _supportedSignatureScheme;
        private HashType _hashType;

        public EcdsaCertificate(X509Certificate2 certificate, X509Certificate2Collection chain)
        {
            _certificate = certificate;
            _privateKey = _certificate.GetECDsaPrivateKey();
            var curve = _privateKey.ExportParameters(false);
            if(curve.Curve.CurveType != System.Security.Cryptography.ECCurve.ECCurveType.Named)
            {
                ExceptionHelper.ThrowException(new InvalidOperationException());
            }
            switch(curve.Curve.Oid.FriendlyName)
            {
                case "nistP256":
                    
                    _supportedSignatureScheme = SignatureScheme.ecdsa_secp256r1_sha256;
                    _hashType = HashType.SHA256;
                    break;
                case "nistP384":
                    _supportedSignatureScheme = SignatureScheme.ecdsa_secp384r1_sha384;
                    _hashType = HashType.SHA384;
                    break;
                case "nistP521":
                    _supportedSignatureScheme = SignatureScheme.ecdsa_secp521r1_sha512;
                    _hashType = HashType.SHA512;
                    break;
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    break;
            }
            _certificateChain = new byte[chain.Count][];
            for (var i = 0; i < chain.Count; i++)
            {
                _certificateChain[i] = chain[i].RawData;
            }
            
        }

        public byte[][] CertificateChain => _certificateChain;
        public byte[] CertificateData => _certificate.RawData;
        public CertificateType CertificateType => CertificateType.ecdsa;

        public string HostName
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public int SignatureSize(SignatureScheme scheme)
        {
            return _privateKey.KeySize /8;
        }

        public unsafe int SignHash(IHashProvider provider, SignatureScheme scheme, ref WritableBuffer writer, byte* message, int messageLength)
        {
            var hash = provider.GetHashInstance(_hashType);
            hash.HashData(message, messageLength);

            var digest = new byte[hash.HashSize];
            fixed (byte* dPtr = digest)
            {
                hash.InterimHash(dPtr, digest.Length);
            }
            
            var result = _privateKey.SignHash(digest);
            var enc = new System.Security.Cryptography.AsnEncodedData(_certificate.SignatureAlgorithm, result);
            
            writer.Write(result);
            return result.Length;
        }

        public bool SupportsSignatureScheme(SignatureScheme scheme)
        {
            return _supportedSignatureScheme == scheme;
        }

        public void Dispose()
        {
        }

        public SignatureScheme ModifySignatureScheme(SignatureScheme signatureScheme)
        {
            return _supportedSignatureScheme;
        }
    }
}
