using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

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

    }
}
