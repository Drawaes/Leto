using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    internal unsafe class Tls1_2Consts
    {
        private const string MASTER_SECRET = "master secret";
        private const string KEY_EXPANSION = "key expansion";
        private const string CLIENT_FINISHED = "client finished";
        private const string SERVER_FINISHED = "server finished";
        
        internal static readonly IntPtr MasterSecretLabelPointer = Marshal.StringToHGlobalAnsi(MASTER_SECRET);
        internal static readonly IntPtr KeyExpansionLabelPointer = Marshal.StringToHGlobalAnsi(KEY_EXPANSION);
        internal static readonly IntPtr ClientFinishedLabelPointer = Marshal.StringToHGlobalAnsi(CLIENT_FINISHED);
        internal static readonly IntPtr ServerFinishedLabelPointer = Marshal.StringToHGlobalAnsi(SERVER_FINISHED);

        internal static readonly int MasterSecretLabelSize = MASTER_SECRET.Length;
        internal static readonly int KeyExpansionLabelSize = KEY_EXPANSION.Length;
        internal static readonly int ClientFinishedLabelSize = CLIENT_FINISHED.Length;
        internal static readonly int ServerFinishedLabelSize = SERVER_FINISHED.Length;
        internal const int MASTER_SECRET_LENGTH = 48;
        internal const int VERIFY_DATA_LENGTH = 12;

        internal static Span<byte> GetClientFinishedSpan() => new Span<byte>((void*)ClientFinishedLabelPointer, ClientFinishedLabelSize);
        internal static Span<byte> GetServerFinishedSpan() => new Span<byte>((void*)ServerFinishedLabelPointer, ServerFinishedLabelSize);
        internal static Span<byte> GetKeyExpansionSpan() => new Span<byte>((void*)KeyExpansionLabelPointer, KeyExpansionLabelSize);
        internal static Span<byte> GetMasterSecretSpan() => new Span<byte>((void*)MasterSecretLabelPointer, MasterSecretLabelSize);
    }
}
