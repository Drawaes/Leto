using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.PlatformAbstractions;

namespace SampleHttpServer.Http
{
    public class FileCache
    {
        Dictionary<string, CacheItem> _cacheItems = new Dictionary<string, CacheItem>();

        public FileCache()
        {
            var filePath = Path.Combine(PlatformServices.Default.Application.ApplicationBasePath, "content");

            string currentPath = "";
            ParseFolder(filePath, currentPath);
        }

        public void ParseFolder(string diskDir, string relativeDir)
        {
            var fileList = Directory.GetFiles(diskDir, "*.*", SearchOption.TopDirectoryOnly);
            foreach (var f in fileList)
            {
                string path = relativeDir + f.Substring(diskDir.Length);
                path = path.Replace("\\", "/");
                string contentType;
                if(Path.GetExtension(f) == ".html")
                {
                    contentType = "text/html";
                }
                else
                {
                    contentType = "text/plain";
                }
                var item = new CacheItem()
                {
                    Content = File.ReadAllBytes(f),
                    ContentType = Encoding.UTF8.GetBytes(contentType),
                    Path = path
                };
                _cacheItems.Add(item.Path, item);
                if(Path.GetFileName(f) == "index.html")
                {
                    path = path.Substring(0, path.Length - Path.GetFileName(f).Length);
                    _cacheItems.Add(path, item);
                }
            }
            var dirs = Directory.GetDirectories(diskDir);
            foreach(var dir in dirs)
            {
                var newdir = relativeDir + dir.Substring(diskDir.Length);
                ParseFolder(dir, newdir);  
            }
        }

        public CacheItem GetCacheItem(string path)
        {
            CacheItem item;
            if(_cacheItems.TryGetValue(path, out item))
            {
                return item;
            }
            return null;
        }

        public class CacheItem
        {
            public byte[] ContentType { get;set;}
            public byte[] Content { get;set;}
            public string Path { get;set;}
        }
    }
}
