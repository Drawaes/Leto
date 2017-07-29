using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(d2i_PKCS12))]
        private extern unsafe static PKCS12 Internal_d2i_PKCS12(IntPtr type, void* pp, int length);

        public unsafe static PKCS12 d2i_PKCS12(Span<byte> input)
        {
            fixed (void* ptr = &input.DangerousGetPinnableReference())
            {
                var tmpPointer = ptr;
                var pk = Internal_d2i_PKCS12(IntPtr.Zero, &tmpPointer, input.Length);
                if (pk.IsInvalid)
                {
                    ThrowOnNullPointer(null);
                }
                return pk;
            }

        }
    }
}
