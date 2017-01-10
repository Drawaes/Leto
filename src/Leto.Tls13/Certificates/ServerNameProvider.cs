using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Text.Primitives;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13.Certificates
{
    public class ServerNameProvider
    {
        private string[] _supportedHostNames;
        private bool _requiresMatch;

        public ServerNameProvider()
            : this( new string[0], false)
        {
            
        }

        public ServerNameProvider(string[] hostNames, bool requiresMatch)
        {
            _supportedHostNames = hostNames;
            _requiresMatch = requiresMatch;
        }
        
        public bool RequiresMatch => _requiresMatch; 


        public void MatchServerName(ReadableBuffer buffer, ConnectionState state)
        {
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            while (buffer.Length > 0)
            {
                var nameType = buffer.ReadBigEndian<byte>();
                buffer = buffer.Slice(sizeof(byte));
                var nameBuffer = BufferExtensions.SliceVector<ushort>(ref buffer);
                if (nameType == 0)
                {
                    state.ServerName = nameBuffer.GetUtf8String();
                }
            }
        }
    }
}
