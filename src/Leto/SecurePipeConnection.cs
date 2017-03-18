using Leto.ConnectionStates;
using Leto.RecordLayer;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;

namespace Leto
{
    public class SecurePipeConnection : IPipeConnection
    {
        private IPipe _inputPipe;
        private IPipe _outputPipe;
        private IPipe _handshakePipe;
        private IPipeConnection _connection;
        private IConnectionState _state;
        private ISecurePipeListener _listener;
        private readonly RecordHandler _recordReader;

        public SecurePipeConnection(PipeFactory pipeFactory, IPipeConnection connection, ISecurePipeListener listener)
        {
            _recordReader = new RecordHandler(this);
            _listener = listener;
            _state = new ServerUnknownVersionState((state) => _state = state, this);
            _inputPipe = pipeFactory.Create();
            _outputPipe = pipeFactory.Create();
            _connection = connection;
            _handshakePipe = pipeFactory.Create();
            var ignore = ReadingLoop();
        }

        internal ISecurePipeListener Listener => _listener;
        internal IPipeConnection Connection => _connection;
        internal IPipe HandshakePipe => _handshakePipe;
        public IPipeReader Input => _outputPipe.Reader;
        public IPipeWriter Output => _inputPipe.Writer;
        internal IConnectionState State => _state;

        private async Task ReadingLoop()
        {
            try
            {
                while(true)
                {
                    var result = await _connection.Input.ReadAsync();
                    var buffer = result.Buffer;
                    try
                    {
                        while(_recordReader.ReadRecord(ref buffer, out ReadableBuffer messageBuffer) == RecordState.Record)
                        {
                            switch(_recordReader.CurrentRecordType)
                            {
                                case RecordType.Handshake:
                                    var handshakeWriter = _handshakePipe.Writer.Alloc();
                                    handshakeWriter.Append(messageBuffer);
                                    await handshakeWriter.FlushAsync();
                                    break;
                                case RecordType.Application:
                                    //TODO: Check that it is a valid time to accept application data
                                    var applicationWriter = _handshakePipe.Writer.Alloc();
                                    applicationWriter.Append(messageBuffer);
                                    await applicationWriter.FlushAsync();
                                    break;
                                case RecordType.Alert:
                                case RecordType.ChangeCipherSpec:
                                default:
                                    throw new NotImplementedException();
                            }
                        }
                    }
                    finally
                    {
                        _connection.Input.Advance(buffer.Start, buffer.End);
                    }
                }
            }
            finally
            {
                _connection.Input.Complete();
            }
        }
        
        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
