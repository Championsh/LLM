namespace System.IO
{
    public static class Path
    {
        public static string Combine(
            string path1,
            string path2
        )
        {
            return path1 + "/" + path2;
        }

        public static string Combine(
            string path1,
            string path2,
            string path3
        )
        {
            return path1 + "/" + path2 + "/" + path3;
        }

        public static string Combine(
            string path1,
            string path2,
            string path3,
            string path4
        )
        {
            return path1 + "/" + path2 + "/" + path3 + "/" + path4;
        }

        public static string Combine(
            params string[] paths
        )
        {
            string path = "";
            foreach (var p in paths)
            {
                path += p;
            }
            return path;
        }
    }
}