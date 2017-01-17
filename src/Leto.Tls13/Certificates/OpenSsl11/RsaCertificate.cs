using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;
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

        public byte[][] CertificateChain
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public void Dispose()
        {
            _key.Free();
            _certificate.Free();
            GC.SuppressFinalize(this);
        }

        public bool SupportsSignatureScheme(SignatureScheme scheme)
        {
            switch (scheme)
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
            return EVP_PKEY_size(_key);
        }

        public unsafe int SignHash(IHashProvider provider, SignatureScheme scheme, ref WritableBuffer writer, byte* message, int messageLength)
        {
            var keySize = SignatureSize(scheme);
            IntPtr hashType;

            switch (scheme)
            {
                case SignatureScheme.rsa_pkcs1_sha256:
                case SignatureScheme.rsa_pss_sha256:
                    hashType = EVP_sha256;
                    break;
                case SignatureScheme.rsa_pkcs1_sha512:
                case SignatureScheme.rsa_pss_sha512:
                    hashType = EVP_sha512;
                    break;
                case SignatureScheme.rsa_pkcs1_sha384:
                case SignatureScheme.rsa_pss_sha384:
                    hashType = EVP_sha384;
                    break;
                default:
                    ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(scheme)));
                    hashType = IntPtr.Zero;
                    break;
            }

            EVP_MD_CTX ctx = EVP_MD_CTX_new();
            EVP_PKEY_CTX pctx;
            GCHandle handle;
            try
            {
                ThrowOnError(EVP_DigestSignInit(ctx, &pctx, hashType, IntPtr.Zero, _key));
                ThrowIfNegative(EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_type.EVP_PKEY_RSA, EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_TYPE_SIG,
                                        EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_MD, 0,(void*) hashType));
                if ((((ushort)scheme) & 0x00FF) == 1)
                {
                    ThrowIfNegative(EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_type.EVP_PKEY_RSA, EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_NONE
                        , EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_RSA_PADDING, (int)RSA_PADDING.RSA_PKCS1_PADDING, null));
                }
                else
                {
                    //PSS Padding
                    ThrowIfNegative(EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_type.EVP_PKEY_RSA, EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_SIGN
                        , EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_RSA_PADDING, (int)RSA_PADDING.RSA_PKCS1_PSS_PADDING, null));
                    ThrowIfNegative(EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_type.EVP_PKEY_RSA, EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_SIGN
                        , EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_RSA_PSS_SALTLEN, 32, null));
                }
                ThrowOnError(EVP_DigestUpdate(ctx, message, messageLength));
                var size = UIntPtr.Zero;
                ThrowOnError(EVP_DigestSignFinal(ctx, null, ref size));
                writer.Ensure((int)size);
                var output = writer.Memory.GetPointer(out handle);
                ThrowOnError(EVP_DigestSignFinal(ctx, output, ref size));
                writer.Advance((int)size);
                return (int)size;
            }
            finally
            {
                ctx.Free();
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        ~RsaCertificate()
        {
            Dispose();
        }
    }
}
