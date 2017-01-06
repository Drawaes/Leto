using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
		internal unsafe static int ThrowOnError(int returnCode)
        {
			if(returnCode != 1)
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
        
        internal static IntPtr ThrowOnError(IntPtr returnCode)
        {
            if(returnCode.ToInt64() < 1)
            {
                throw new NotImplementedException();
            }
            return returnCode;
        }
        
    }
}
