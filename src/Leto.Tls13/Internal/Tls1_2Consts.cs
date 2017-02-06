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
        
        internal static readonly IntPtr MasterSecretPointer = Marshal.StringToHGlobalAnsi(MASTER_SECRET);
        internal static readonly IntPtr KeyExpansion = Marshal.StringToHGlobalAnsi(KEY_EXPANSION);
        internal static readonly IntPtr ClientFinishedPointer = Marshal.StringToHGlobalAnsi(CLIENT_FINISHED);
        internal static readonly IntPtr ServerFinishedPointer = Marshal.StringToHGlobalAnsi(SERVER_FINISHED);

        internal static readonly int MasterSecretSize = MASTER_SECRET.Length;
        internal static readonly int KeyExpansionSize = KEY_EXPANSION.Length;
        internal static readonly int ClientFinishedSize = CLIENT_FINISHED.Length;
        internal static readonly int ServerFinishedSize = SERVER_FINISHED.Length;
        internal const int MasterSecretLength = 48;

        internal static Span<byte> GetClientFinishedSpan() => new Span<byte>((void*)ClientFinishedPointer, ClientFinishedSize);
        internal static Span<byte> GetServerFinishedSpan() => new Span<byte>((void*)ServerFinishedPointer, ServerFinishedSize);
        internal static Span<byte> GetKeyExpansionSpan() => new Span<byte>((void*)KeyExpansion, KeyExpansionSize);
    }
}
