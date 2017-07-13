using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines.Text.Primitives;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace SocketServer
{
    public partial class HttpConnection<TContext> : IHttpRequestFeature, IHttpResponseFeature, IFeatureCollection
    {
        private FeatureCollection _features = new FeatureCollection();

        public object this[Type key]
        {
            get => GetFeature(key);

            set =>            SetFeature(key, value);
        }

        private object GetFeature(Type key)
        {
            if (key == typeof(IHttpRequestFeature))
            {
                return this;
            }

            if (key == typeof(IHttpResponseFeature))
            {
                return this;
            }

            return _features[key];
        }

        private void SetFeature(Type key, object value) => _features[key] = value;

        public bool HasStarted { get; set; }

        Stream IHttpRequestFeature.Body
        {
            get => throw new NotImplementedException();// _requestBody;

            set
            {

            }
        }

        Stream IHttpResponseFeature.Body
        {
            get => throw new NotImplementedException();// _responseBody;

            set
            {

            }
        }

        IHeaderDictionary IHttpResponseFeature.Headers
        {
            get => throw new NotSupportedException();

            set => throw new NotSupportedException();
        }

        IHeaderDictionary IHttpRequestFeature.Headers
        {
            get => RequestHeaders;
            set => throw new NotSupportedException();
        }

        public bool IsReadOnly => false;

        private string _method;
        string IHttpRequestFeature.Method
        {
            get
            {
                if (_method == null)
                {
                    _method = Method.GetAsciiString();
                }

                return _method;
            }
            set => _method = value;
        }

        private string _path;
        string IHttpRequestFeature.Path
        {
            get
            {
                if (_path == null)
                {
                    _path = Path.GetAsciiString();
                }
                return _path;
            }
            set => _path = value;
        }

        public string PathBase { get; set; }

        public string Protocol { get; set; }

        public string QueryString { get; set; }

        public string RawTarget { get; set; }

        public string ReasonPhrase { get; set; }

        public int Revision { get; set; }

        public string Scheme { get; set; } = "http";

        public int StatusCode { get; set; }

        public TFeature Get<TFeature>() => (TFeature)this[typeof(TFeature)];

        public IEnumerator<KeyValuePair<Type, object>> GetEnumerator() => throw new NotImplementedException();

        public void OnCompleted(Func<object, Task> callback, object state) => throw new NotImplementedException();

        public void OnStarting(Func<object, Task> callback, object state) => throw new NotImplementedException();

        public void Set<TFeature>(TFeature instance) => this[typeof(TFeature)] = instance;

        IEnumerator IEnumerable.GetEnumerator() => throw new NotSupportedException();
    }
}
