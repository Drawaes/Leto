using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Handshake
{
    public class Extensions
    {
        public static void ProcessExtensionList(ReadableBuffer buffer, State.ConnectionState connectionState)
        {
            if(buffer.Length < sizeof(ushort))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var listLength = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(sizeof(ushort));
            if(buffer.Length < listLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            while(buffer.Length > 3)
            {
                var extensionType = buffer.ReadBigEndian<ExtensionType>();
                var extensionLength = buffer.Slice(sizeof(ExtensionType)).ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ExtensionType) + sizeof(ushort));
                if(buffer.Length < extensionLength)
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
                }
                var extensionBuffer = buffer.Slice(0, extensionLength);
                buffer = buffer.Slice(extensionLength);
                switch(extensionType)
                {
                    case ExtensionType.key_share:
                    case ExtensionType.pre_shared_key:
                    case ExtensionType.supported_groups:
                    case ExtensionType.signature_algorithms:
                    case ExtensionType.supported_versions:
                    case ExtensionType.certificate_authorities:
                        break;
                }
            }
            if(buffer.Length != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
        }
    }
}
