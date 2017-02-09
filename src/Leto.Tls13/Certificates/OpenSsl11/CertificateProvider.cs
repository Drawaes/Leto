using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.Certificates.OpenSsl11
{
    public class CertificateProvider
    {
        public unsafe ICertificate LoadCertificate(X509Certificate2 certificate, X509CertificateCollection certificateChain)
        {
            var data = certificate.Export(X509ContentType.Pkcs12, "");
            IntPtr pk12Pointer = IntPtr.Zero;
            fixed (byte* ptr = data)
            {
                byte* ptr2 = ptr;
                pk12Pointer = d2i_PKCS12(ref pk12Pointer, ref ptr2, data.Length);
            }
            try
            {
                EVP_PKEY key;
                X509 x509;
                ThrowOnError(PKCS12_parse(pk12Pointer, "", out key, out x509, IntPtr.Zero));
                var altString = GetNameString(x509);
                byte[][] certChain = new byte[certificateChain.Count][];
                for(int i = 0; i < certChain.Length;i++)
                {
                    certChain[i] = certificateChain[i].Export(X509ContentType.Cert);
                }
                return GetCertificate(key, x509, certificate.RawData, altString, certChain);
            }
            finally
            {
                PKCS12_free(pk12Pointer);
            }
        }

        public unsafe ICertificate LoadPfx12(string filename, string password)
        {
            var bytes = System.IO.File.ReadAllBytes(filename);
            IntPtr pk12Pointer = IntPtr.Zero;
            IntPtr stackPtr;
            fixed (byte* ptr = bytes)
            {
                byte* ptr2 = ptr;
                pk12Pointer = d2i_PKCS12(ref pk12Pointer, ref ptr2, bytes.Length);
            }
            try
            {
                EVP_PKEY key;
                X509 x509;
                ThrowOnError(PKCS12_parse(pk12Pointer, password, out key, out x509, out stackPtr));
                var altString = GetNameString(x509);
                var numberinstack = OPENSSL_sk_num(stackPtr);
                if(numberinstack == -1)
                {
                    numberinstack = 0;
                }
                else
                {
                    numberinstack -= 1;
                    OPENSSL_sk_pop(stackPtr);
                }
                var certlist = new byte[numberinstack][];
                for(int i = 0; i < numberinstack;i++)
                {
                    var currentCert = OPENSSL_sk_pop(stackPtr);
                    certlist[i] = GetCertDER(currentCert);
                    var c = new X509();
                    c.Ptr = currentCert;
                    var tring = GetNameString(c);
                }
                OPENSSL_sk_free(stackPtr);
                
                return GetCertificate(key, x509, GetCertDER(x509.Ptr), altString, certlist.Reverse().ToArray());
            }
            finally
            {
                PKCS12_free(pk12Pointer);
            }
        }

        private unsafe byte[] GetCertDER(IntPtr cert)
        {
            var certDerSize = i2d_X509(cert, null);
            var derData = new byte[certDerSize];

            fixed (byte* cerPtr = derData)
            {
                byte* outPtr = cerPtr;
                certDerSize = i2d_X509(cert, &outPtr);
                derData = derData.Slice(0,certDerSize).ToArray();
            }
            return derData;
        }

        public unsafe ICertificate LoadCertificate(string certificate, string privateKey)
        {
            var bio = BIO_new(BIO_s_mem);
            try
            {
                var keyBytes = Encoding.ASCII.GetBytes(privateKey);
                var certBytes = Encoding.ASCII.GetBytes(certificate);
                fixed (byte* kPtr = keyBytes)
                fixed (byte* cPtr = certBytes)
                {
                    BIO_write(bio, kPtr, keyBytes.Length);
                    var pKey = PEM_read_bio_PrivateKey(bio, null, null, null);
                    BIO_write(bio, cPtr, certBytes.Length);
                    var x509 = PEM_read_bio_X509(bio, null, null, null);
                    byte* buffPtr = null;
                    var certDerSize = i2d_X509(x509, null);
                    var derData = new byte[certDerSize];

                    fixed (byte* cerPtr = derData)
                    {
                        byte* outPtr = cerPtr;
                        certDerSize = i2d_X509(x509, &outPtr);
                        var altString = GetNameString(x509);
                        return GetCertificate(pKey, x509, derData, altString, null);
                    }
                }
            }
            finally
            {
                bio.Free();
            }
            throw new NotImplementedException();
        }

        private static ICertificate GetCertificate(EVP_PKEY key, X509 x509, byte[] derCertificateData, string altName, byte[][] certChain)
        {
            var name = OBJ_nid2ln(EVP_PKEY_base_id(key));
            switch (name)
            {
                case "id-ecPublicKey":
                    return new EcdsaCertificate(key, x509, derCertificateData, altName, certChain);
                case "rsaEncryption":
                    return new RsaCertificate(key, x509, derCertificateData, altName);
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
