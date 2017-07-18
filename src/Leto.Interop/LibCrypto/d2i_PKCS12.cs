using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(d2i_PKCS12))]
        private extern unsafe static PKCS12 Internal_d2i_PKCS12(PKCS12 type, void* pp, int length);

        public unsafe static PKCS12 d2i_PKCS12(Span<byte> input)
        {
            fixed (void* ptr = &input.DangerousGetPinnableReference())
            {
                var tmpPointer = ptr;
                var pk = Internal_d2i_PKCS12(default(PKCS12), &tmpPointer, input.Length);
                if (!pk.IsValid)
                {
                    ThrowOnNullPointer(null);
                }
                return pk;
            }

        }
    }
}
