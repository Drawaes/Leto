using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        internal static readonly IntPtr EVP_aes_128_gcm = Internal_EVP_aes_128_gcm();
        internal static readonly IntPtr EVP_aes_256_gcm = Internal_EVP_aes_256_gcm();
        internal static readonly IntPtr EVP_aes_128_ccm = Internal_EVP_aes_128_ccm();
        internal static readonly IntPtr EVP_chacha20_poly1305 = Internal_EVP_chacha20_poly1305();

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_aes_128_gcm")]
        private static extern IntPtr Internal_EVP_aes_128_gcm();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_aes_128_gcm")]
        private static extern IntPtr Internal_EVP_aes_128_ccm();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_aes_256_gcm")]
        private static extern IntPtr Internal_EVP_aes_256_gcm();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_chacha20_poly1305")]
        private static extern IntPtr Internal_EVP_chacha20_poly1305();

        internal enum EVP_CIPHER_CTRL : int
        {
            EVP_CTRL_INIT = 0x0,
            EVP_CTRL_SET_KEY_LENGTH = 0x1,
            EVP_CTRL_GET_RC2_KEY_BITS = 0x2,
            EVP_CTRL_SET_RC2_KEY_BITS = 0x3,
            EVP_CTRL_GET_RC5_ROUNDS = 0x4,
            EVP_CTRL_SET_RC5_ROUNDS = 0x5,
            EVP_CTRL_RAND_KEY = 0x6,
            EVP_CTRL_PBE_PRF_NID = 0x7,
            EVP_CTRL_COPY = 0x8,
            EVP_CTRL_GCM_SET_IVLEN = 0x9,
            EVP_CTRL_GCM_GET_TAG = 0x10,
            EVP_CTRL_GCM_SET_TAG = 0x11,
            EVP_CTRL_GCM_SET_IV_FIXED = 0x12,
            EVP_CTRL_GCM_IV_GEN = 0x13,
            EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN,
            EVP_CTRL_CCM_GET_TAG = EVP_CTRL_GCM_GET_TAG,
            EVP_CTRL_CCM_SET_TAG = EVP_CTRL_GCM_SET_TAG,
            EVP_CTRL_CCM_SET_L = 0x14,
            EVP_CTRL_CCM_SET_MSGLEN = 0x15,
        }
    }
}
