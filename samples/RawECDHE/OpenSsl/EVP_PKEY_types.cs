using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        internal enum EVP_PKEY_type : int
        {
            EVP_PKEY_EC = 408,
            EVP_PKEY_RSA = 6
        }

        internal enum EVP_PKEY_Ctrl_Command : int
        {
            EVP_PKEY_ALG_CTRL = 0x1000,
            EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1,
            EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 3,
            EVP_PKEY_CTRL_MD = 1,
            EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1),
            EVP_PKEY_CTRL_EC_PARAM_ENC = (EVP_PKEY_ALG_CTRL + 2),
            EVP_PKEY_CTRL_EC_ECDH_COFACTOR = (EVP_PKEY_ALG_CTRL + 3),
            EVP_PKEY_CTRL_EC_KDF_TYPE = (EVP_PKEY_ALG_CTRL + 4),
            EVP_PKEY_CTRL_EC_KDF_MD = (EVP_PKEY_ALG_CTRL + 5),
            EVP_PKEY_CTRL_GET_EC_KDF_MD = (EVP_PKEY_ALG_CTRL + 6),
            EVP_PKEY_CTRL_EC_KDF_OUTLEN = (EVP_PKEY_ALG_CTRL + 7),
            EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN = (EVP_PKEY_ALG_CTRL + 8),
            EVP_PKEY_CTRL_EC_KDF_UKM = (EVP_PKEY_ALG_CTRL + 9),
            EVP_PKEY_CTRL_GET_EC_KDF_UKM = (EVP_PKEY_ALG_CTRL + 10),
        }

        [Flags]
        internal enum EVP_PKEY_Ctrl_OP : int
        {
            EVP_PKEY_OP_NONE = -1,
            EVP_PKEY_OP_UNDEFINED = 0,
            EVP_PKEY_OP_PARAMGEN = (1 << 1),
            EVP_PKEY_OP_KEYGEN = (1 << 2),
            EVP_PKEY_OP_SIGN = (1 << 3),
            EVP_PKEY_OP_VERIFY = (1 << 4),
            EVP_PKEY_OP_VERIFYRECOVER = (1 << 5),
            EVP_PKEY_OP_SIGNCTX = (1 << 6),
            EVP_PKEY_OP_VERIFYCTX = (1 << 7),
            EVP_PKEY_OP_ENCRYPT = (1 << 8),
            EVP_PKEY_OP_DECRYPT = (1 << 9),
            EVP_PKEY_OP_DERIVE = (1 << 10),
            EVP_PKEY_OP_TYPE_SIG = (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER | EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX),
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_PKEY
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (IsValid) return;
                EVP_PKEY_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
