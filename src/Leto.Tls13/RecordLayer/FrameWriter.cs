using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Tls13.Internal;
using Leto.Tls13.State;

namespace Leto.Tls13.RecordLayer
{
    public class FrameWriter
    {
        private readonly IConnectionState _state;
        private bool _frameStarted = false;
        private int _plainTextSize;
        private int _messageBodySize;
        private Memory<byte> _bookmark;
        private RecordType _recordType;

        public FrameWriter(IConnectionState state)
        {
            _state = state;
        }

        public void StartFrame(RecordType recordType, ref WritableBuffer buffer)
        {
            if (_frameStarted)
            {
                ExceptionHelper.ThrowException(new InvalidOperationException("Already writing a frame and started another"));
            }
            _recordType = recordType;
            buffer.Ensure(RecordProcessor.RecordHeaderLength);
            buffer.WriteBigEndian(recordType);
            buffer.WriteBigEndian(_state.TlsRecordVersion);
            _bookmark = buffer.Memory;
            buffer.WriteBigEndian<ushort>(0);
            _messageBodySize = buffer.BytesWritten;
            if (_state.WriteKey == null)
            {
                return;
            }
            _state.WriteKey.WriteNonce(ref buffer);
            _plainTextSize = buffer.BytesWritten;
        }

        public void FinishFrame(ref WritableBuffer buffer)
        {
            if (_state.WriteKey != null)
            {
                _plainTextSize = buffer.BytesWritten - _plainTextSize;
                _state.WriteKey.EncryptWithAuthData(ref buffer, _recordType, _state.TlsRecordVersion, _plainTextSize);
            }
            _messageBodySize = buffer.BytesWritten - _messageBodySize;
            _bookmark.Span.Write16BitNumber((ushort)_messageBodySize);
        }
    }
}
