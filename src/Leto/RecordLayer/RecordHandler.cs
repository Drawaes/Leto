using Leto.BulkCiphers;
using System;
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
        private int _currentWaitingMessageSize = 0;
        private RecordType _currentRecordType;
        private SecurePipeConnection _connection;

        public RecordHandler(SecurePipeConnection secureConnection)
        {
            _connection = secureConnection;
        }

        public RecordType CurrentRecordType => _currentRecordType;

        //Still needs the decrypt phase but that can be added later.
        public RecordState ReadRecord(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer)
        {
            if (_currentWaitingMessageSize == 0)
            {
                if (buffer.Length < _minimumMessageSize)
                {
                    messageBuffer = default(ReadableBuffer);
                    return RecordState.Incomplete;
                }
                var header = buffer.Slice(0, _minimumMessageSize).ToSpan().Read<RecordHeader>();
                buffer = buffer.Slice(_minimumMessageSize);
                _currentRecordType = header.RecordType;
                _currentWaitingMessageSize = header.RecordLength;
                //TODO: CHECK THE VERSION
            }
            if(buffer.Length < _currentWaitingMessageSize)
            {
                messageBuffer = default(ReadableBuffer);
                return RecordState.Incomplete;
            }
            //We have a full record slice it out
            messageBuffer = buffer.Slice(0, _currentWaitingMessageSize);
            buffer = buffer.Slice(_currentWaitingMessageSize);
            _currentWaitingMessageSize = 0;
            return RecordState.Record;
        }

        //Still needs encrypt phase but that can be added later.
        public async Task WriteRecords(IPipeReader pipeReader, RecordType recordType)
        {
            //We assume there is data waiting to be flushed this will be a single pass not a loop
            var reader = await pipeReader.ReadAsync();
            var buffer = reader.Buffer;
            try
            {
                ReadableBuffer append;
                while(buffer.Length > 0)
                {
                    append = buffer.Slice(0, Math.Min(_maxMessageSize, buffer.Length));
                    buffer = buffer.Slice(append.End);
                    var recordHeader = new RecordHeader()
                    {
                        RecordType = recordType,
                        RecordLength = (ushort)append.Length,
                        RecordVersion = _connection.State.RecordVersion
                    };
                    var output = _connection.Connection.Output.Alloc();
                    output.Ensure(_minimumMessageSize);
                    output.Memory.Span.Write(recordHeader);
                    output.Advance(_minimumMessageSize);
                    output.Append(append);
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
