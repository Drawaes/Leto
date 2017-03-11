using Leto.RecordLayer;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.Alerts
{
    public class AlertException : Exception
    {
        private readonly AlertLevel _alertLevel;
        private readonly AlertDescription _alertDescription;

        public AlertException(AlertLevel alertLevel, AlertDescription description)
        {
            _alertLevel = alertLevel;
            _alertDescription = description;
        }

        public AlertLevel Level => _alertLevel;
        public AlertDescription Description => _alertDescription;
        public override string Message => $"A {_alertLevel} {_alertDescription}";

        public override string ToString() => Message;

        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerHidden()]
        public static void ThrowAlert(AlertLevel alertLeve, AlertDescription description, string message)
        {
            Console.WriteLine($"Writing alert {alertLeve}-{description} message {message}");
            throw new AlertException(alertLeve, description);
        }

        
    }
}
