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
        public const int PlainTextMaxSize = 2 << 13;
        public const int RecordHeaderLength = 5;

        public static RecordType ReadRecord(ref ReadableBuffer messageBuffer, State.IConnectionState state)
        {
            if (messageBuffer.Length < RecordHeaderLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "The message buffer length is smaller than the record header length");
            }
            var recordType = messageBuffer.ReadBigEndian<RecordType>();
            var version = messageBuffer.Slice(sizeof(RecordType)).ReadBigEndian<ushort>();
            var size = messageBuffer.Slice(sizeof(RecordType) + sizeof(ushort)).ReadBigEndian<ushort>();
            if (state?.ReadKey == null)
            {
                messageBuffer = messageBuffer.Slice(RecordHeaderLength);
                return recordType;
            }
            if ((TlsVersion)state.TlsRecordVersion == TlsVersion.Tls12)
            {
                state.ReadKey.DecryptWithAuthData(ref messageBuffer);
                return recordType;
            }
            else
            {
                messageBuffer = messageBuffer.Slice(RecordHeaderLength);
                state.ReadKey.Decrypt(ref messageBuffer);
                RemovePadding(ref messageBuffer);
                recordType = messageBuffer.Slice(messageBuffer.Length - sizeof(RecordType)).ReadBigEndian<RecordType>();
                messageBuffer = messageBuffer.Slice(0, messageBuffer.Length - sizeof(RecordType));
                return recordType;
            }
        }
        
        //public static void WriteRecord(ref WritableBuffer buffer, RecordType recordType, ReadableBuffer plainText, State.IConnectionState state)
        //{
        //    buffer.Ensure(RecordHeaderLength);
        //    if (state.WriteKey == null)
        //    {
        //        buffer.WriteBigEndian(recordType);
        //        buffer.WriteBigEndian(state.TlsRecordVersion);
        //        buffer.WriteBigEndian((ushort)plainText.Length);
        //        buffer.Append(plainText);
        //        return;
        //    }
        //    if ((TlsVersion)state.TlsRecordVersion == TlsVersion.Tls12)
        //    {
        //        buffer.WriteBigEndian(recordType);
        //        buffer.WriteBigEndian(state.TlsRecordVersion);
        //        buffer.WriteBigEndian((ushort)(plainText.Length + (state.WriteKey.IVLength - 4) + state.WriteKey.Overhead));
        //        state.WriteKey.EncryptWithAuthData(ref buffer, plainText, recordType, state.TlsRecordVersion);
        //    }
        //    else
        //    {
        //        buffer.WriteBigEndian(RecordType.Application);
        //        buffer.WriteBigEndian(state.TlsRecordVersion);
        //        var totalSize = plainText.Length + state.WriteKey.Overhead + sizeof(RecordType);
        //        buffer.WriteBigEndian((ushort)totalSize);
        //        state.WriteKey.Encrypt(ref buffer, plainText, recordType);
        //    }
        //}

        private static void RemovePadding(ref ReadableBuffer buffer)
        {
            while (buffer.Slice(buffer.Length - 1).Peek() == 0)
            {
                buffer = buffer.Slice(0, buffer.Length - 1);
            }
        }

        public static bool TryGetFrame(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            messageBuffer = default(ReadableBuffer);
            if (buffer.Length < 5)
            {
                return false;
            }
            var frameType = buffer.ReadBigEndian<RecordType>();
            if (frameType != RecordType.Alert && frameType != RecordType.Application
                && frameType != RecordType.Handshake && frameType != RecordType.ChangeCipherSpec)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, $"unknown frame type {frameType}");
            }
            var version = buffer.Slice(1).ReadBigEndian<ushort>();
            if (version < 0x0300 || version > 0x0400)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, $"The frame version was outside the range {version}");
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
    }
}
