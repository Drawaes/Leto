using System;
using System.Binary;
using System.IO.Pipelines;
using Leto.Alerts;

namespace Leto.RecordLayer
{
    public sealed class GeneralRecordHandler : RecordHandler
    {
        public GeneralRecordHandler(SecurePipeConnection secureConnection) : base(secureConnection)
        {
        }

        public override RecordState ReadRecord(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            messageBuffer = default(ReadableBuffer);
            if (buffer.Length < _minimumMessageSize) return RecordState.Incomplete;
            var header = buffer.Slice(0, _minimumMessageSize).ToSpan().Read<RecordHeader>();
            if (buffer.Length < header.Length + _minimumMessageSize) return RecordState.Incomplete;
            _currentRecordType = header.RecordType;
            if (_connection.State.ReadKey == null)
            {
                messageBuffer = buffer.Slice(_minimumMessageSize, header.Length);
                buffer = buffer.Slice(messageBuffer.End);
            }
            else
            {
                messageBuffer = buffer.Slice(_minimumMessageSize, header.Length);
                buffer = buffer.Slice(messageBuffer.End);
                _connection.State.ReadKey.Decrypt(ref messageBuffer, header.RecordType, header.Version);
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
                Version = _connection.State.RecordVersion
            };
            if(_connection.State.WriteKey != null)
            {
                recordHeader.Length += (ushort)(8 + _connection.State.WriteKey.Overhead);
            }
            var writer = _connection.Connection.Output.Alloc(sizeof(RecordHeader));
            writer.Buffer.Span.Write(recordHeader);
            writer.Advance(sizeof(RecordHeader));
            if (_connection.State.WriteKey != null)
            {
                _connection.State.WriteKey.Encrypt(ref writer, span, RecordType.Alert, _connection.State.RecordVersion);
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
                    Version = _connection.State.RecordVersion
                };
                writer.Ensure(_minimumMessageSize);
                if (_connection.State.WriteKey != null)
                {
                    recordHeader.Length += (ushort)(8 + _connection.State.WriteKey.Overhead);
                }
                writer.Buffer.Span.Write(recordHeader);
                writer.Advance(_minimumMessageSize);
                if (_connection.State.WriteKey != null)
                {
                    _connection.State.WriteKey.Encrypt(ref writer, append, recordType, _connection.State.RecordVersion);
                }
                else
                {
                    writer.Append(append);
                }
            }
        }
    }
}
