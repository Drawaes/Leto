using Leto.ConnectionStates;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto
{
    public class SecurePipeConnection : IPipeConnection
    {
        private IPipe _inputPipe;
        private IPipe _outputPipe;
        private IPipeConnection _connection;
        private IConnectionState _state;
        private ISecurePipeListener _listener;

        public SecurePipeConnection(PipeFactory pipeFactory, IPipeConnection connection, ISecurePipeListener listener)
        {
            _listener = listener;
            _state = new ServerUnknownVersionState((state) => _state = state, listener);
            _inputPipe = pipeFactory.Create();
            _outputPipe = pipeFactory.Create();
            _connection = connection;
        }

        public IConnectionState State => _state;
        public IPipeReader Input => _outputPipe.Reader;
        public IPipeWriter Output => _inputPipe.Writer;

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
