using System;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using Leto.Internal;

namespace Leto.Alerts
{
    public class AlertException : Exception
    {
        public AlertException(AlertLevel alertLevel, AlertDescription description, string message) : base(message)
        {
            Level = alertLevel;
            Description = description;
        }

        public AlertException(ReadableBuffer buffer)
            :this(buffer.ToSpan())
        {

        }

        public AlertException(Span<byte> alertSpan)
        {
            var reader = new BigEndianAdvancingSpan(alertSpan);
            Level = reader.Read<AlertLevel>();
            Description = reader.Read<AlertDescription>();
            ReceivedFromPeer = true;
        }

        public AlertLevel Level { get; }
        public AlertDescription Description { get; }
        public bool ReceivedFromPeer { get; }
        public override string Message => $"A {Level} {Description} {base.Message}";

        public override string ToString() => Message;

        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerHidden()]
        public static void ThrowAlert(AlertLevel alertLevel, AlertDescription description, string message) =>
            throw new AlertException(alertLevel, description, message);
        public static void ThrowFailedHandshake(string message) =>
            ThrowAlert(AlertLevel.Fatal, AlertDescription.handshake_failure, message);
        public static void ThrowUnexpectedMessage(RecordLayer.RecordType recordType) =>
            ThrowAlert(AlertLevel.Fatal, AlertDescription.unexpected_message, $"Unexpected message of type {recordType}");
        public static void ThrowUnexpectedMessage(Handshake.HandshakeType handshakeType) =>
            ThrowAlert(AlertLevel.Fatal, AlertDescription.unexpected_message, $"Unexpected message of type {handshakeType}");
        public static void ThrowInvalidLength(int expected, int actual) =>
            ThrowAlert(AlertLevel.Fatal, AlertDescription.decode_error, $"Invalid vector length expected {expected} actual {actual}");
        public static void ThrowDecode(string message) =>
            ThrowAlert(AlertLevel.Fatal, AlertDescription.decode_error, message);
        public static void ThrowApplicationProtocol(byte[] protocol) =>
            ThrowAlert(AlertLevel.Fatal, AlertDescription.no_application_protocol, $"Invalid protocol detected {BitConverter.ToString(protocol)}");
    }
}
