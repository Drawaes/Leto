using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.RecordLayer
{
    public sealed class Tls13RecordHandler : RecordHandler
    {
        public Tls13RecordHandler(SecurePipeConnection secureConnection) : base(secureConnection)
        {
        }

        public override RecordState ReadRecord(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            if (buffer.Length < _minimumMessageSize)
            {
                messageBuffer = default(ReadableBuffer);
                return RecordState.Incomplete;
            }
            var header = buffer.Slice(0, _minimumMessageSize).ToSpan().Read<RecordHeader>();
            if (buffer.Length < header.Length + _minimumMessageSize)
            {
                messageBuffer = default(ReadableBuffer);
                return RecordState.Incomplete;
            }
            messageBuffer = buffer.Slice(_minimumMessageSize, header.Length);
            buffer = buffer.Slice(messageBuffer.End);
            _connection.State.ReadKey.Decrypt(ref messageBuffer, header.RecordType, header.Version);
            //RemovePadding(ref messageBuffer);
            _currentRecordType = buffer.Slice(buffer.Length - sizeof(RecordType)).ReadBigEndian<RecordType>();
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - sizeof(RecordType));
            return RecordState.Record;
        }

        protected override void WriteRecords(ref ReadableBuffer buffer, ref WritableBuffer writer, RecordType recordType)
        {
            ReadableBuffer append;
            while (buffer.Length > 0)
            {
                append = buffer.Slice(0, Math.Min(_maxMessageSize, buffer.Length));
                buffer = buffer.Slice(append.End);
                var recordHeader = new RecordHeader()
                {
                    RecordType = RecordType.Application,
                    Length = (ushort)append.Length,
                    Version = _connection.State.RecordVersion
                };
                writer.Ensure(_minimumMessageSize);
                recordHeader.Length += (ushort)(sizeof(RecordType) + _connection.State.WriteKey.Overhead);
                writer.Buffer.Span.Write(recordHeader);
                writer.Advance(_minimumMessageSize);
                _connection.State.WriteKey.Encrypt(ref writer, append, recordType, _connection.State.RecordVersion);
            }
        }
    }
}
