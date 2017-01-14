using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Leto.Tls13.RecordLayer;

namespace Leto.Tls13.Alerts
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

        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerHidden()]
        public static void ThrowAlert(AlertLevel alertLeve, AlertDescription description)
        {
            throw new AlertException(alertLeve, description);
        }

        public override string Message
        {
            get
            {
                return $"A {_alertLevel} {_alertDescription}";
            }
        }

        public override string ToString()
        {
            return Message;
        }
        
        public static void WriteAlert(RecordProcessor recordHandler, ref WritableBuffer output, AlertLevel level, AlertDescription description)
        {
            var buffer = new byte[sizeof(AlertLevel) + sizeof(AlertDescription)];
            var span = new Span<byte>(buffer);
            span.Write(level);
            span = span.Slice(sizeof(AlertLevel));
            span.Write(description);
            recordHandler.WriteRecord(ref output, RecordType.Alert, buffer);
        }
    }
}
