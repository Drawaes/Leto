using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_PKEY_derive(EVP_PKEY_CTX ctx, void* key, ref IntPtr keylen);

        public static unsafe int EVP_PKEY_derive(EVP_PKEY keyPair, EVP_PKEY peerKey, Span<byte> output)
        {
            var ctx = EVP_PKEY_CTX_new(keyPair, IntPtr.Zero);
            try
            {
                var result = EVP_PKEY_derive_init(ctx);
                ThrowOnErrorReturnCode(result);
                result = EVP_PKEY_derive_set_peer(ctx, peerKey);
                ThrowOnErrorReturnCode(result);

                var size = IntPtr.Zero;
                result = EVP_PKEY_derive(ctx, null, ref size);
                ThrowOnErrorReturnCode(result);
                if(size.ToInt32() > output.Length)
                {
                    throw new ArgumentOutOfRangeException(nameof(output));
                }
                fixed(void* outputPtr = &output.DangerousGetPinnableReference())
                {
                    size = (IntPtr) output.Length;
                    result = EVP_PKEY_derive(ctx, outputPtr, ref size);
                    ThrowOnErrorReturnCode(result);
                    return size.ToInt32();
                }
            }
            finally
            {
                ctx.Free();
            }
        }
    }
}
