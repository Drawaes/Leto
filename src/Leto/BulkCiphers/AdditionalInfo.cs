using Leto.RecordLayer;
using System.Runtime;
using System.Runtime.InteropServices;

namespace Leto.BulkCiphers
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct AdditionalInfo
    {
        private ulong _sequenceNumber;
        private RecordType _recordType;
        private ushort _tlsVersion;
        private ushort _plainTextLength;

        public ulong SequenceNumber { get => UnsafeUtilities.Reverse(_sequenceNumber); set => _sequenceNumber = UnsafeUtilities.Reverse(value); }
        public RecordType RecordType { get => _recordType; set => _recordType = value; }
        public ushort TlsVersion { get => UnsafeUtilities.Reverse(_tlsVersion); set => _tlsVersion = UnsafeUtilities.Reverse(value); }
        public ushort PlainTextLength { get => UnsafeUtilities.Reverse(_plainTextLength); set => _plainTextLength = UnsafeUtilities.Reverse(value); }
        public ushort PlainTextLengthBigEndian { set => _plainTextLength = value; }
    }
}
