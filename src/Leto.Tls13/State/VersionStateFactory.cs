using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Extensions;
using Leto.Tls13.Handshake;
using Microsoft.Extensions.Logging;

namespace Leto.Tls13.State
{
    public class VersionStateFactory
    {
        private static readonly TlsVersion[] _supportedVersion = new TlsVersion[]
        {
            TlsVersion.Tls12,
            TlsVersion.Tls13Draft18
        };
        
        public static IConnectionState GetNewStateMachine(ReadableBuffer buffer, SecurePipeListener listener, ILogger logger)
        {
            switch(GetVersion(ref buffer))
            {
                case TlsVersion.Tls12:
                    return new ServerStateTls12(listener, logger);
                case TlsVersion.Tls13Draft18:
                    return new ServerStateTls13Draft18(listener, logger);
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, "Unsupported version");
                    return null;
            }
        }

        private static TlsVersion GetVersion(ref ReadableBuffer buffer)
        {
            //Jump the version header and the randoms
            buffer = buffer.Slice(HandshakeProcessor.HandshakeHeaderSize);
            TlsVersion version;
            buffer = buffer.SliceBigEndian(out version);
            if (!_supportedVersion.Contains(version))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, $"The version was not in the supported list {version}");
            }
            //Slice out the random
            buffer = buffer.Slice(Hello.RandomLength);
            //No sessions slice and dump
            BufferExtensions.SliceVector<byte>(ref buffer);
            //Skip the cipher suites if we find a version we are happy with
            //then the cipher suite is dealt with by that version
            BufferExtensions.SliceVector<ushort>(ref buffer);
            //Skip compression, we don't care about that either, we just want to get to the end
            BufferExtensions.SliceVector<byte>(ref buffer);
            //And here we are at the end, if we have no extensions then we must be the header version that
            //we accepted earlier
            if (buffer.Length == 0)
            {
                return version;
            }
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            while(buffer.Length >= 8)
            {
                ExtensionType type;
                buffer = buffer.SliceBigEndian(out type);
                var ext = BufferExtensions.SliceVector<ushort>(ref buffer);
                if(type == ExtensionType.supported_versions)
                {
                    //Scan the version for supported ones
                    return ExtensionsRead.ReadSupportedVersion(ext, _supportedVersion);
                }
            }
            return version;
        }
    }
}
