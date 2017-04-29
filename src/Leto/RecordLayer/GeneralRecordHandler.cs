using System;
using System.Binary;
using System.IO.Pipelines;
using Leto.Alerts;
using Leto.BulkCiphers;

namespace Leto.RecordLayer
{
    public sealed class GeneralRecordHandler : RecordHandler
    {
        public GeneralRecordHandler(IKeyPair secureConnection, TlsVersion recordVersion, IPipeWriter output) : base(secureConnection, recordVersion, output)
        {
        }

        public override RecordState ReadRecord(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            messageBuffer = default(ReadableBuffer);
            if (buffer.Length < _minimumMessageSize) return RecordState.Incomplete;
            var header = buffer.Slice(0, _minimumMessageSize).ToSpan().Read<RecordHeader>();
            if (buffer.Length < header.Length + _minimumMessageSize) return RecordState.Incomplete;
            _currentRecordType = header.RecordType;
            if (_connection?.ReadKey == null)
            {
                messageBuffer = buffer.Slice(_minimumMessageSize, header.Length);
                buffer = buffer.Slice(messageBuffer.End);
            }
            else
            {
                messageBuffer = buffer.Slice(_minimumMessageSize, header.Length);
                buffer = buffer.Slice(messageBuffer.End);
                _connection.ReadKey.Decrypt(ref messageBuffer, header.RecordType, header.Version);
            }
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
                RecordType = RecordType.Alert,
                Length = (ushort)span.Length,
                Version = _recordVersion
            };
            if (_connection?.WriteKey != null)
            {
                recordHeader.Length += (ushort)(8 + _connection.WriteKey.Overhead);
            }
            var writer = _output.Alloc(sizeof(RecordHeader));
            writer.Buffer.Span.Write(recordHeader);
            writer.Advance(sizeof(RecordHeader));
            if (_connection?.WriteKey != null)
            {
                _connection.WriteKey.Encrypt(ref writer, span, RecordType.Alert, _recordVersion);
            }
            else
            {
                writer.Write(span);
            }
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
                    RecordType = recordType,
                    Length = (ushort)append.Length,
                    Version = _recordVersion
                };
                writer.Ensure(_minimumMessageSize);
                if (_connection?.WriteKey != null)
                {
                    recordHeader.Length += (ushort)(8 + _connection.WriteKey.Overhead);
                }
                writer.Buffer.Span.Write(recordHeader);
                writer.Advance(_minimumMessageSize);
                if (_connection?.WriteKey != null)
                {
                    _connection.WriteKey.Encrypt(ref writer, append, recordType, _recordVersion);
                }
                else
                {
                    writer.Append(append);
                }
            }
        }
    }
}
