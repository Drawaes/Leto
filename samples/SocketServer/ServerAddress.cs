using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace SocketServer
{
    public class ServerAddress
    {
        public string Host { get; private set; }
        public string PathBase { get; private set; }
        public int Port { get; internal set; }
        public string Scheme { get; private set; }

        public override string ToString() => Scheme.ToLowerInvariant() + "://" + Host.ToLowerInvariant() + ":" + Port.ToString(CultureInfo.InvariantCulture) + PathBase.ToLowerInvariant();

        public override int GetHashCode() => ToString().GetHashCode();

        public override bool Equals(object obj)
        {
            var other = obj as ServerAddress;
            if (other == null)
            {
                return false;
            }
            return string.Equals(Scheme, other.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase)
                && Port == other.Port
                && string.Equals(PathBase, other.PathBase, StringComparison.OrdinalIgnoreCase);
        }

        public static ServerAddress FromUrl(string url)
        {
            url = url ?? string.Empty;

            var schemeDelimiterStart = url.IndexOf("://", StringComparison.Ordinal);
            if (schemeDelimiterStart < 0)
            {
                throw new FormatException($"Invalid URL: {url}");
            }
            var schemeDelimiterEnd = schemeDelimiterStart + "://".Length;

            var pathDelimiterStart = url.IndexOf("/", schemeDelimiterEnd, StringComparison.Ordinal);
            var pathDelimiterEnd = pathDelimiterStart;

            if (pathDelimiterStart < 0)
            {
                pathDelimiterStart = pathDelimiterEnd = url.Length;
            }

            var serverAddress = new ServerAddress
            {
                Scheme = url.Substring(0, schemeDelimiterStart)
            };

            var hasSpecifiedPort = false;

            var portDelimiterStart = url.LastIndexOf(":", pathDelimiterStart - 1, pathDelimiterStart - schemeDelimiterEnd, StringComparison.Ordinal);
            if (portDelimiterStart >= 0)
            {
                var portDelimiterEnd = portDelimiterStart + ":".Length;

                var portString = url.Substring(portDelimiterEnd, pathDelimiterStart - portDelimiterEnd);
                if (int.TryParse(portString, NumberStyles.Integer, CultureInfo.InvariantCulture, out var portNumber))
                {
                    hasSpecifiedPort = true;
                    serverAddress.Host = url.Substring(schemeDelimiterEnd, portDelimiterStart - schemeDelimiterEnd);
                    serverAddress.Port = portNumber;
                }
            }

            if (!hasSpecifiedPort)
            {
                if (string.Equals(serverAddress.Scheme, "http", StringComparison.OrdinalIgnoreCase))
                {
                    serverAddress.Port = 80;
                }
                else if (string.Equals(serverAddress.Scheme, "https", StringComparison.OrdinalIgnoreCase))
                {
                    serverAddress.Port = 443;
                }
            }


            if (!hasSpecifiedPort)
            {
                serverAddress.Host = url.Substring(schemeDelimiterEnd, pathDelimiterStart - schemeDelimiterEnd);
            }

            if (string.IsNullOrEmpty(serverAddress.Host))
            {
                throw new FormatException($"Invalid URL: {url}");
            }

            // Path should not end with a / since it will be used as PathBase later
            if (url[url.Length - 1] == '/')
            {
                serverAddress.PathBase = url.Substring(pathDelimiterEnd, url.Length - pathDelimiterEnd - 1);
            }
            else
            {
                serverAddress.PathBase = url.Substring(pathDelimiterEnd);
            }

            return serverAddress;
        }

        internal ServerAddress WithHost(string host) =>
            new ServerAddress
            {
                Scheme = Scheme,
                Host = host,
                Port = Port,
                PathBase = PathBase
            };
    }
}
