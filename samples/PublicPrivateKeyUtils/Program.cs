using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace PublicPrivateKeyUtils
{
    public class Program
    {
        public const string ecdsaKeyPEM = @"-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBrsoKp0oqcv6/JovJJDoDVSGWdirrkgCWxrprGlzB9o0X8fV675X0
NwuBenXFfeZvVcwluO7/Q9wkYoPd/t3jGImgBwYFK4EEACOhgYkDgYYABAFj36bL
06h5JRGUNB1X/Hwuw64uKW2GGJLVPPhoYMcg/ALWaW+d/t+DmV5xikwKssuFq4Bz
VQldyCXTXGgu7OC0AQCC/Y/+ODK3NFKlRi+AsG3VQDSV4tgHLqZBBus0S6pPcg1q
kohxS/xfFg/TEwRSSws+roJr4JFKpO2t3/be5OdqmQ==
-----END EC PRIVATE KEY-----
";
        static Dictionary<string, List<byte>> _sections = new Dictionary<string, List<byte>>();

        [DllImport(Interop.Libraries.NCrypt, CharSet = CharSet.Unicode)]
        internal static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
        [DllImport(Interop.Libraries.NCrypt, CharSet = CharSet.Unicode)]
        internal static extern int NCryptImportKey(IntPtr hProvider, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, out IntPtr phKey, IntPtr pbData, uint cbData, uint dwFlags);

        public unsafe static void Main(string[] args)
        {
            var thumb = "48026c976caaf7f3a72d38c17d16ce69d04a6053".ToUpper();
            var cert = LoadCertificateFromStore(thumb, false, StoreLocation.CurrentUser, StoreName.My);
            var privKey = cert.GetECDsaPrivateKey();
            var curve = privKey.ExportParameters(true);



            List<byte> currentSection = null;
            var lines = ecdsaKeyPEM.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].StartsWith("-----BEGIN"))
                {
                    //Starting a block
                    string blockName = lines[i].Substring("-----BEGIN ".Length, lines[i].LastIndexOf("-----") - "-----BEGIN ".Length);
                    currentSection = new List<byte>();
                    _sections.Add(blockName, currentSection);
                    continue;
                }
                else if (lines[i].StartsWith("-----END"))
                {
                    //ending block
                    currentSection = null;
                }
                currentSection?.AddRange(Convert.FromBase64String(lines[i].Trim()));
            }

            IntPtr prov, key;
            var res = NCryptOpenStorageProvider(out prov, "Microsoft Software Key Storage Provider", 0);

            //ECDSA_P521

            var size = sizeof(BCRYPT_ECCKEY_BLOB);
            var blobHeader = new BCRYPT_ECCKEY_BLOB()
            {
                Magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC,
                cbKey = _sections["EC PRIVATE KEY"].Count
            };

            var desc = new BCryptBufferDesc()
            {
                cBuffers = 1
            };
            var buff = new BCryptBuffer()
            {
                BufferType = NCryptBufferDescriptors.NCRYPTBUFFER_ECC_CURVE_NAME,
                cbBuffer = "ECDSA_P521\0".Length * 2,
                pvBuffer = Marshal.StringToHGlobalUni("ECDSA_P521\0")
            };
            var buffPtr = Marshal.AllocHGlobal(sizeof(BCryptBuffer));
            Marshal.StructureToPtr(buff,buffPtr, true);
            desc.pBuffers = buffPtr;
            var descPtr = Marshal.AllocHGlobal(sizeof(BCryptBufferDesc));
            Marshal.StructureToPtr(desc, descPtr, true);

            var bytes = new byte[size + blobHeader.cbKey];
            _sections["EC PRIVATE KEY"].ToArray().CopyTo(bytes, size);
            fixed (void* blobPtr = bytes)
            {
                Unsafe.Copy(blobPtr, ref blobHeader);

                res = NCryptImportKey(prov, IntPtr.Zero, "ECCPRIVATEBLOB", descPtr, out key, (IntPtr)blobPtr, (uint)bytes.Length, 0);
            }
        }

        public static X509Certificate2 LoadCertificateFromStore(string thumbprint, bool pullChain, StoreLocation storeLocation = StoreLocation.CurrentUser, StoreName storeName = StoreName.My)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.MaxAllowed);
                var certList = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
                
                var cert = certList[0];
                var chain = new X509Chain();
                var chainCertificates = new X509Certificate2Collection();
                if (chain.Build(cert))
                {
                    //We have a chain so we can reverse the chain (we need to send the certificates with the 
                    //root last for TLS
                    for (int i = chain.ChainElements.Count - 1; i > -1; i--)
                    {
                        chainCertificates.Add(chain.ChainElements[i].Certificate);
                    }
                }
                return cert;
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_ECCKEY_BLOB
        {
            internal KeyBlobMagicNumber Magic;
            internal int cbKey;
        }

        internal enum KeyBlobMagicNumber : int
        {
            BCRYPT_DSA_PUBLIC_MAGIC = 0x42505344,
            BCRYPT_DSA_PRIVATE_MAGIC = 0x56505344,
            BCRYPT_DSA_PUBLIC_MAGIC_V2 = 0x32425044,
            BCRYPT_DSA_PRIVATE_MAGIC_V2 = 0x32565044,

            BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345,
            BCRYPT_ECDH_PRIVATE_P256_MAGIC = 0x324B4345,
            BCRYPT_ECDH_PUBLIC_P384_MAGIC = 0x334B4345,
            BCRYPT_ECDH_PRIVATE_P384_MAGIC = 0x344B4345,
            BCRYPT_ECDH_PUBLIC_P521_MAGIC = 0x354B4345,
            BCRYPT_ECDH_PRIVATE_P521_MAGIC = 0x364B4345,
            BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = 0x504B4345,
            BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = 0x564B4345,

            BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345,
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345,
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345,
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345,
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345,
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345,
            BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC = 0x50444345,
            BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC = 0x56444345,

            BCRYPT_RSAPUBLIC_MAGIC = 0x31415352,
            BCRYPT_RSAPRIVATE_MAGIC = 0x32415352,
            BCRYPT_RSAFULLPRIVATE_MAGIC = 0x33415352,
            BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCryptBuffer
        {
            internal int cbBuffer;             // Length of buffer, in bytes
            internal NCryptBufferDescriptors BufferType; // Buffer type
            internal IntPtr pvBuffer;          // Pointer to buffer
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCryptBufferDesc
        {
            internal int ulVersion;            // Version number
            internal int cBuffers;             // Number of buffers
            internal IntPtr pBuffers;          // Pointer to array of BCryptBuffers
        }

        /// <summary>
        ///     NCrypt buffer descriptors
        /// </summary>
        internal enum NCryptBufferDescriptors : int
        {
            NCRYPTBUFFER_ECC_CURVE_NAME = 60,
        }
    }
}
