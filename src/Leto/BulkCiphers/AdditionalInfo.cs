using Leto.RecordLayer;
using System.Runtime;
using System.Runtime.InteropServices;
using static Leto.BufferExtensions;

namespace Leto.BulkCiphers
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct AdditionalInfo
    {
        private ulong _sequenceNumber;
        private RecordType _recordType;
        private TlsVersion _tlsVersion;
        private ushort _plainTextLength;

        public ulong SequenceNumber { get => Reverse(_sequenceNumber); set => _sequenceNumber = Reverse(value); }
        public RecordType RecordType { get => _recordType; set => _recordType = value; }
        public TlsVersion TlsVersion { get => Reverse(_tlsVersion); set => _tlsVersion = Reverse(value); }
        public ushort PlainTextLength { get => Reverse(_plainTextLength); set => _plainTextLength = Reverse(value); }
        public ushort PlainTextLengthBigEndian { set => _plainTextLength = value; }
    }
}
