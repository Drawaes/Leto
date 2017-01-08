using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;

namespace Leto.Tls13.RecordLayer
{
    public class RecordProcessor
    {
        public const int RecordHeaderLength = 5;
        public const int PlainTextMaxSize = 2 << 14;
        private const ushort TlsRecordVersion = 0x0301;
        private State.ConnectionState _state;
        
        public RecordProcessor(State.ConnectionState state)
        {
            _state = state;
        }

        public RecordType ReadRecord(ref ReadableBuffer messageBuffer)
        {
            if (messageBuffer.Length < 5)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var recordType = messageBuffer.ReadBigEndian<RecordType>();
            var version = messageBuffer.Slice(sizeof(RecordType)).ReadBigEndian<ushort>();
            var size = messageBuffer.Slice(sizeof(RecordType) + sizeof(ushort)).ReadBigEndian<ushort>();
            messageBuffer = messageBuffer.Slice(RecordHeaderLength);
            if (_state.ReadKey == null)
            {
                return recordType;
            }
            _state.ReadKey.Decrypt(ref messageBuffer);
            RemovePadding(ref messageBuffer);
            recordType = messageBuffer.Slice(messageBuffer.Length - sizeof(RecordType)).ReadBigEndian<RecordType>();
            messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - sizeof(RecordType));
            _state.ReadKey.IncrementSequence();
            return recordType;
        }

        public void WriteRecord(ref WritableBuffer buffer, RecordType recordType, ReadableBuffer plainText)
        {
            buffer.Ensure(RecordHeaderLength);
            if (_state.WriteKey == null)
            {
                buffer.WriteBigEndian(recordType);
                buffer.WriteBigEndian(TlsRecordVersion);
                buffer.WriteBigEndian((ushort)plainText.Length);
                buffer.Append(plainText);
                return;
            }
            buffer.WriteBigEndian(RecordType.Application);
            buffer.WriteBigEndian(TlsRecordVersion);
            var totalSize = plainText.Length + _state.WriteKey.Overhead + sizeof(RecordType);
            buffer.WriteBigEndian((ushort)totalSize);
            _state.WriteKey.Encrypt(ref buffer, plainText, recordType);
            _state.WriteKey.IncrementSequence();
        }

        public bool TryGetFrame(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            messageBuffer = default(ReadableBuffer);
            if (buffer.Length < 5)
            {
                return false;
            }
            var frameType = buffer.ReadBigEndian<RecordType>();
            if (frameType != RecordType.Alert && frameType != RecordType.Application
                && frameType != RecordType.Handshake)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var version = buffer.Slice(1).ReadBigEndian<ushort>();
            if (version < 0x0300 || version > 0x0400)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var length = buffer.Slice(3).ReadBigEndian<ushort>();
            if (buffer.Length >= (length + RecordHeaderLength))
            {
                messageBuffer = buffer.Slice(0, length + RecordHeaderLength);
                buffer = buffer.Slice(length + RecordHeaderLength);
                return true;
            }
            return false;
        }

        private void RemovePadding(ref ReadableBuffer buffer)
        {
            while (buffer.Slice(buffer.Length - 1).Peek() == 0)
            {
                buffer = buffer.Slice(0, buffer.Length - 1);
            }
        }
    }
}
