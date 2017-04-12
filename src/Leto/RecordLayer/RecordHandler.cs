using System;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using Leto.Alerts;

namespace Leto.RecordLayer
{
    public abstract class RecordHandler
    {
        protected static readonly int _maxMessageSize = 16 * 1024 - _minimumMessageSize;
        protected static readonly int _minimumMessageSize = Marshal.SizeOf<RecordHeader>();
        protected RecordType _currentRecordType;
        protected SecurePipeConnection _connection;
        protected object _connectionOutputLock = new object();

        public RecordHandler(SecurePipeConnection secureConnection) => _connection = secureConnection;

        public RecordType CurrentRecordType => _currentRecordType;

        public void WriteRecords(IPipeReader pipeReader, RecordType recordType)
        {
            lock (_connectionOutputLock)
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
        }

        public WritableBufferAwaitable WriteRecordsAndFlush(ref ReadableBuffer readableBuffer, RecordType recordType)
        {
            lock (_connectionOutputLock)
            {
                var output = _connection.Connection.Output.Alloc();
                WriteRecords(ref readableBuffer, ref output, recordType);
                return output.FlushAsync();
            }
        }

        protected abstract void WriteRecords(ref ReadableBuffer buffer, ref WritableBuffer writer, RecordType recordType);
        public abstract RecordState ReadRecord(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer);
        public void WriteHandshakeRecords() => WriteRecords(_connection.HandshakeOutput.Reader, RecordType.Handshake);
        public abstract WritableBufferAwaitable WriteAlert(AlertException alert);
    }
}
