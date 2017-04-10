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
        private IPipe _handshakeInput;
        private IPipe _handshakeOutput;
        private IPipeConnection _connection;
        private IConnectionState _state;
        private SecurePipeListener _listener;
        private TaskCompletionSource<SecurePipeConnection> _handshakeComplete = new TaskCompletionSource<SecurePipeConnection>();

        internal SecurePipeConnection(PipeFactory pipeFactory, IPipeConnection connection, SecurePipeListener listener)
        {
            RecordHandler = new GeneralRecordHandler(this);
            _listener = listener;
            _inputPipe = pipeFactory.Create();
            _outputPipe = pipeFactory.Create();
            _connection = connection;
            _handshakeInput = pipeFactory.Create();
            _handshakeOutput = pipeFactory.Create();
            _state = new ServerUnknownVersionState((state) => _state = state, this);
            var ignore = ReadingLoop();
        }

        public IPipeReader Input => _outputPipe.Reader;
        public IPipeWriter Output => _inputPipe.Writer;
        public Task<SecurePipeConnection> HandshakeAwaiter => _handshakeComplete.Task;
        internal SecurePipeListener Listener => _listener;
        internal IPipeConnection Connection => _connection;
        internal IPipe HandshakeInput => _handshakeInput;
        internal IPipe HandshakeOutput => _handshakeOutput;
        internal IConnectionState State => _state;
        internal RecordHandler RecordHandler { get; set; }

        private async Task ReadingLoop()
        {
            try
            {
                while (true)
                {
                    var result = await _connection.Input.ReadAsync();
                    var buffer = result.Buffer;
                    try
                    {
                        while (RecordHandler.ReadRecord(ref buffer, out ReadableBuffer messageBuffer) == RecordState.Record)
                        {
                            switch (RecordHandler.CurrentRecordType)
                            {
                                case RecordType.Handshake:
                                    var handshakeWriter = _handshakeInput.Writer.Alloc();
                                    handshakeWriter.Append(messageBuffer);
                                    handshakeWriter.Commit();
                                    if (_state.ProcessHandshake())
                                    {
                                        var w = _connection.Output.Alloc();
                                        await w.FlushAsync();
                                    }
                                    if (_state.HandshakeComplete)
                                    {
                                        var ignore = ReadingApplicationDataLoop();
                                        _handshakeComplete.TrySetResult(this);
                                    }
                                    break;
                                case RecordType.Application:
                                    if (!_state.HandshakeComplete)
                                    {
                                        Alerts.AlertException.ThrowUnexpectedMessage(RecordType.Application);
                                    }
                                    var applicationWriter = _outputPipe.Writer.Alloc();
                                    applicationWriter.Append(messageBuffer);
                                    await applicationWriter.FlushAsync();
                                    break;
                                case RecordType.ChangeCipherSpec:
                                    _state.ChangeCipherSpec();
                                    break;
                                case RecordType.Alert:
                                    var alertSpan = messageBuffer.ToSpan();
                                    if (alertSpan[1] == 0)
                                    {
                                        return;
                                    }
                                    throw new NotImplementedException();
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

        private async Task ReadingApplicationDataLoop()
        {
            try
            {
                while (true)
                {
                    var result = await _inputPipe.Reader.ReadAsync();
                    var buffer = result.Buffer;
                    try
                    {
                        await RecordHandler.WriteRecordsAndFlush(ref buffer, RecordType.Application);
                    }
                    finally
                    {
                        _inputPipe.Reader.Advance(buffer.Start, buffer.End);
                    }
                }
            }
            finally
            {
                _connection.Output.Complete();
            }
        }

        public void Dispose()
        {
        }
    }
}
