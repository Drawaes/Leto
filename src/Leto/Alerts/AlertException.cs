using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Leto.Alerts
{
    public class AlertException : Exception
    {
        public AlertException(AlertLevel alertLevel, AlertDescription description, string message)
            :base(message)
        {
            Level = alertLevel;
            Description = description;
        }

        public AlertLevel Level { get; }
        public AlertDescription Description { get; }
        public override string Message => $"A {Level} {Description} {base.Message}";

        public override string ToString() => Message;

        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerHidden()]
        public static void ThrowAlert(AlertLevel alertLevel, AlertDescription description, string message)
        {
            throw new AlertException(alertLevel, description, message);
        }

        public static void ThrowUnexpectedMessage(RecordLayer.RecordType recordType)
        {
            ThrowAlert(AlertLevel.Fatal, AlertDescription.unexpected_message, $"Unexpected message of type {recordType}");
        }

        public static void ThrowUnexpectedMessage(Handshake.HandshakeType handshakeType)
        {
            ThrowAlert(AlertLevel.Fatal, AlertDescription.unexpected_message, $"Unexpected message of type {handshakeType}");
        }

        public static void ThrowInvalidLength(int expected, int actual)
        {
            ThrowAlert(AlertLevel.Fatal, AlertDescription.decode_error, $"Invalid vector length expected {expected} actual {actual}");
        }

        public static void ThrowDecode(string message)
        {
            ThrowAlert(AlertLevel.Fatal, AlertDescription.decode_error, message);
        }
    }
}
