using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Alerts;
using Leto.BulkCiphers;

namespace Leto.RecordLayer
{
    public sealed class Tls13RecordHandler : RecordHandler
    {
        public Tls13RecordHandler(IKeyPair secureConnection, TlsVersion recordVersion, IPipeWriter output) : base(secureConnection, recordVersion, output)
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
            _connection.ReadKey.Decrypt(ref messageBuffer, header.RecordType, header.Version);
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
                Version = TlsVersion.Tls1
            };
            var writer = _output.Alloc((ushort)(sizeof(RecordType) + _connection.WriteKey.Overhead));
            writer.Ensure(_minimumMessageSize);
            recordHeader.Length += (ushort)(sizeof(RecordType) + _connection.WriteKey.Overhead + span.Length);
            writer.Buffer.Span.Write(recordHeader);
            writer.Advance(_minimumMessageSize);
            _connection.WriteKey.Encrypt(ref writer, span, RecordType.Alert, _recordVersion);
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
                    Version = TlsVersion.Tls1
                };
                writer.Ensure(_minimumMessageSize);
                recordHeader.Length += (ushort)(sizeof(RecordType) + _connection.WriteKey.Overhead);
                writer.Buffer.Span.Write(recordHeader);
                writer.Advance(_minimumMessageSize);
                _connection.WriteKey.Encrypt(ref writer, append, recordType, _recordVersion);
            }
        }
    }
}
