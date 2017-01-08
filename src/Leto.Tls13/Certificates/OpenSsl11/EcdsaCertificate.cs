using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
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
        private HashType _hashType;
        private EC_KEY _ecKey;
        
        internal EcdsaCertificate(EVP_PKEY privateKey, X509 certificate, byte[] derCertData, string altNameString)
        {
            _certData = derCertData;
            _key = privateKey;
            _certificate = certificate;
            _altNameString = altNameString;

            _ecKey = EVP_PKEY_get0_EC_KEY(_key);
            var group = EC_KEY_get0_group(_ecKey);
            var curveName = EC_GROUP_get_curve_name(group);
            _curveName = OBJ_nid2ln(curveName);
            switch(_curveName)
            {
                case "secp256r1":
                    _scheme = SignatureScheme.ecdsa_secp256r1_sha256;
                    _hashType = HashType.SHA256;
                    break;
                case "secp384r1":
                    _scheme = SignatureScheme.ecdsa_secp384r1_sha384;
                    _hashType = HashType.SHA384;
                    break;
                case "secp521r1":
                    _scheme = SignatureScheme.ecdsa_secp521r1_sha512;
                    _hashType = HashType.SHA512;
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

        public int SignatureSize(SignatureScheme scheme)
        {
            return ECDSA_size(_ecKey);
        }

        public unsafe Span<byte> SignHash(IHashProvider provider, SignatureScheme scheme, byte* message, int messageLength)
        {
            var hash = provider.GetHashInstance(_hashType);
            var prefix = Enumerable.Repeat((byte)0x20,64).ToArray();
            hash.HashData(prefix);
            var contextLabel = Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify\0");
            
            hash.HashData(contextLabel);
            hash.HashData(message, messageLength);

            var digest = new byte[hash.HashSize];
            fixed (byte* dPtr = digest)
            {
                hash.InterimHash(dPtr, digest.Length);
            }
            
            var output = new byte[ECDSA_size(_ecKey)];
            fixed(byte* oPtr = output)
            fixed(byte* iPtr = digest)
            {
                var sigSize = output.Length;
                ThrowOnError(ECDSA_sign(0, iPtr, digest.Length, oPtr, ref sigSize, _ecKey));
                return output.Slice(0, sigSize);
            }
        }

        ~EcdsaCertificate()
        {
            Dispose();
        }
    }
}
