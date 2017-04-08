using Leto.BulkCiphers;
using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Leto.RecordLayer
{
    public class RecordHandler
    {
        private static Task<RecordState> _cachedIncompleteTask = Task.FromResult(RecordState.Incomplete);
        private static readonly int _maxMessageSize = 16 * 1024 - _minimumMessageSize;
        private static readonly int _minimumMessageSize = Marshal.SizeOf<RecordHeader>();
        private RecordType _currentRecordType;
        private SecurePipeConnection _connection;

        public RecordHandler(SecurePipeConnection secureConnection) => _connection = secureConnection;

        public RecordType CurrentRecordType => _currentRecordType;

        public RecordState ReadRecord(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
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
            _currentRecordType = header.RecordType;
            //TODO: CHECK THE VERSION
            if (_connection.State.ReadKey == null)
            {
                messageBuffer = buffer.Slice(_minimumMessageSize, header.Length);
                buffer = buffer.Slice(messageBuffer.End);
            }
            else
            {
                messageBuffer = buffer.Slice(0, _minimumMessageSize + header.Length);
                buffer = buffer.Slice(messageBuffer.End);
                _connection.State.ReadKey.Decrypt(ref messageBuffer, true);
            }
            return RecordState.Record;
        }

        public void WriteRecords(IPipeReader pipeReader, RecordType recordType)
        {
            if (!pipeReader.TryRead(out ReadResult reader))
            {
                return;
            }
            var buffer = reader.Buffer;
            var output = _connection.Connection.Output.Alloc();
            try
            {
                WriteRecords(ref buffer, ref output, recordType);
            }
            finally
            {
                pipeReader.Advance(buffer.End);
            }
            output.Commit();
        }

        public WritableBufferAwaitable WriteRecordsAndFlush(IPipeReader pipeReader, RecordType recordType)
        {
            var output = _connection.Connection.Output.Alloc();
            if (!pipeReader.TryRead(out ReadResult reader))
            {
                return output.FlushAsync();
            }
            var buffer = reader.Buffer;
            try
            {
                WriteRecords(ref buffer, ref output, recordType);
            }
            finally
            {
                pipeReader.Advance(buffer.End);
            }
            return output.FlushAsync();
        }

        public WritableBufferAwaitable WriteRecordsAndFlush(ref ReadableBuffer readableBuffer, RecordType recordType)
        {
            var output = _connection.Connection.Output.Alloc();
            WriteRecords(ref readableBuffer, ref output, recordType);
            return output.FlushAsync();
        }

        private void WriteRecords(ref ReadableBuffer buffer, ref WritableBuffer writer, RecordType recordType)
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
                    _connection.State.WriteKey.WriteNonce(ref writer);
                    writer.Append(append);
                    _connection.State.WriteKey.EncryptWithAuthData(ref writer, recordType, _connection.State.RecordVersion, append.Length);
                }
                else
                {
                    writer.Append(append);
                }
            }
        }
    }
}
