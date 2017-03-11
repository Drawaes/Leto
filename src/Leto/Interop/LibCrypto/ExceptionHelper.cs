using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [System.Diagnostics.DebuggerHidden()]
        private unsafe static int ThrowOnErrorReturnCode(int returnCode)
        {
            if (returnCode != 1)
            {
                var tempBuffer = new byte[512];
                fixed (byte* buffPointer = tempBuffer)
                {
                    var errCode = ERR_get_error();
                    ERR_error_string_n(errCode, buffPointer, (UIntPtr)tempBuffer.Length);
                    var errorString = Marshal.PtrToStringAnsi((IntPtr)buffPointer);
                    throw new System.Security.SecurityException($"{errCode}-{errorString}");
                }
            }
            return returnCode;
        }
    }
    }
