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
    }
}
