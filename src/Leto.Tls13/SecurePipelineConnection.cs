using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.RecordLayer;

namespace Leto.Tls13
{
    public class SecurePipelineConnection : IPipelineConnection
    {
        private readonly IPipelineConnection _lowerConnection;
        private RecordProcessor _recordHandler;
        private readonly Pipe _outputPipe;
        private readonly Pipe _inputPipe;
        private readonly Pipe _handshakePipe;
        private CryptoProvider _cryptoProvider;
        private State.ConnectionState _state;

        public SecurePipelineConnection(IPipelineConnection pipeline, PipelineFactory factory, CryptoProvider provider)
        {
            _lowerConnection = pipeline;
            _outputPipe = factory.Create();
            _inputPipe = factory.Create();
            _handshakePipe = factory.Create();
            _cryptoProvider = provider;
            _state = new State.ConnectionState(provider);
            _recordHandler = new RecordProcessor(_state);
            StartReading();
            HandshakeReading();
        }

        public IPipelineReader Input => _outputPipe;
        public IPipelineWriter Output => _inputPipe;

        private async void StartReading()
        {
            while (true)
            {
                var result = await _lowerConnection.Input.ReadAsync();
                var buffer = result.Buffer;
                try
                {
                    ReadableBuffer messageBuffer;
                    while (_recordHandler.TryGetFrame(ref buffer, out messageBuffer))
                    {
                        var recordType = _recordHandler.ReadRecord(ref messageBuffer);
                        if (recordType == RecordType.Handshake)
                        {
                            var writer = _handshakePipe.Alloc();
                            writer.Append(messageBuffer);
                            await writer.FlushAsync();
                            continue;
                        }
                        if (recordType == RecordType.Alert)
                        {
                            var level = messageBuffer.ReadBigEndian<Alerts.AlertLevel>();
                            messageBuffer = messageBuffer.Slice(sizeof(Alerts.AlertLevel));
                            var description = messageBuffer.ReadBigEndian<Alerts.AlertDescription>();
                            Alerts.AlertException.ThrowAlert(level, description);
                        }
                        if (recordType == RecordType.Application)
                        {
                            var writer = _outputPipe.Alloc();
                            writer.Append(messageBuffer);
                            await writer.FlushAsync();
                            continue;
                        }
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
                    }
                }
                finally
                {
                    _lowerConnection.Input.Advance(buffer.Start, buffer.End);
                }
            }
        }

        private async void HandshakeReading()
        {
            while (true)
            {
                var result = await _handshakePipe.ReadAsync();
                var buffer = result.Buffer;
                try
                {
                    ReadableBuffer messageBuffer;
                    Handshake.HandshakeType handshakeType;
                    while(Handshake.HandshakeProcessor.TryGetFrame(ref buffer, _state, out messageBuffer, out handshakeType))
                    {
                        switch(handshakeType)
                        {
                            case Handshake.HandshakeType.client_hello:
                                Handshake.Hello.ProcessClientHello(messageBuffer, _state);
                                break;
                            default:
                                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
                                break;
                        }
                    }
                }
                finally
                {
                    _handshakePipe.AdvanceReader(buffer.Start, buffer.End);
                }
            }
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
