using System;
using System.Collections.Generic;
using System.IO.Pipelines.Networking.Tls.Managed.Internal.Interop.Windows;
using System.Linq;
using System.Threading.Tasks;
using static Interop.NCrypt;

namespace Leto.Tls13.Interop.Windows
{
    internal class ExceptionHelper
    {
        internal static void CheckReturnCode(global::Interop.BCrypt.NTSTATUS returnCode)
        {
            if (returnCode != 0)
            {
                throw new InvalidOperationException($"Api Error {returnCode}");
            }
        }

        internal static void CheckReturnCode(ErrorCode returnCode)
        {
            if (returnCode != ErrorCode.ERROR_SUCCESS)
            {
                throw new InvalidOperationException($"Api Error {returnCode}");
            }
        }

        internal static void CheckReturnCode(NTResult returnCode)
        {
            if (returnCode != 0)
            {
                throw new InvalidOperationException($"Api Error {returnCode}");
            }
        }
    }
}
