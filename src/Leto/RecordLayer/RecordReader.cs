using Leto.BulkCiphers;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Leto.RecordLayer
{
    public class RecordReader
    {
        private static Task<RecordState> _cachedIncompleteTask = Task.FromResult(RecordState.Incomplete);
        private static readonly int _minimumMessageSize = Marshal.SizeOf<RecordHeader>();
        private int _currentWaitingMessageSize = 0;
        private RecordType _currentRecordType;
        
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
    }
}
