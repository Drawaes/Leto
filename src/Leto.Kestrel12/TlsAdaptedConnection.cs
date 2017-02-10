using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Adapter;

namespace Leto.Kestrel12
{
    public class TlsAdaptedConnection : IAdaptedConnection
    {
        private Stream _stream;
        private SecurePipelineConnection _connection;

        public TlsAdaptedConnection(SecurePipelineConnection connection)
        {
            _connection = connection;
            _stream = _connection.GetStream();
        }

        public Stream ConnectionStream => _stream;

        public void PrepareRequest(IFeatureCollection requestFeatures)
        {
        }
    }
}
