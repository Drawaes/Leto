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

        public async Task WriteRecords(IPipeReader pipeReader, RecordType recordType)
        {
            //We assume there is data waiting to be flushed this will be a single pass not a loop
            //We then can use this in a loop for app data or to flush a single set of data for the
            //handshakes
            var reader = await pipeReader.ReadAsync();
            var buffer = reader.Buffer;
            try
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
                    var output = _connection.Connection.Output.Alloc();
                    output.Ensure(_minimumMessageSize);
                    if(_connection.State.WriteKey != null)
                    {
                        recordHeader.Length += (ushort)(8 + _connection.State.WriteKey.Overhead);
                    }
                    output.Buffer.Span.Write(recordHeader);
                    output.Advance(_minimumMessageSize);
                    if (_connection.State.WriteKey != null)
                    {
                        _connection.State.WriteKey.WriteNonce(ref output);
                        output.Append(append);
                        _connection.State.WriteKey.EncryptWithAuthData(ref output, recordType, _connection.State.RecordVersion, append.Length);
                    }
                    else
                    {
                        output.Append(append);
                    }
                    await output.FlushAsync();
                }
            }
            finally
            {
                pipeReader.Advance(buffer.End);
            }

        }
    }
}
