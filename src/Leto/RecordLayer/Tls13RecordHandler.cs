using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Alerts;

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
            _currentRecordType = messageBuffer.Slice(messageBuffer.Length - sizeof(RecordType)).ReadBigEndian<RecordType>();
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - sizeof(RecordType));
            return RecordState.Record;
        }

        public unsafe override WritableBufferAwaitable WriteAlert(AlertException alert)
        {
            ushort data = 0;
            var span = new Span<byte>(&data, 2);
            span[0] = (byte)alert.Level;
            span[1] = (byte)alert.Description;
            var recordHeader = new RecordHeader()
            {
                RecordType = RecordType.Application,
                Length = (ushort)span.Length,
                Version = _connection.State.RecordVersion
            };
            var writer = _connection.Connection.Output.Alloc((ushort)(sizeof(RecordType) + _connection.State.WriteKey.Overhead));
            writer.Ensure(_minimumMessageSize);
            recordHeader.Length += (ushort)(sizeof(RecordType) + _connection.State.WriteKey.Overhead + span.Length);
            writer.Buffer.Span.Write(recordHeader);
            writer.Advance(_minimumMessageSize);
            _connection.State.WriteKey.Encrypt(ref writer, span, RecordType.Alert, _connection.State.RecordVersion);
            return writer.FlushAsync();
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
