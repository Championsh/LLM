using System.Collections.Generic;

namespace System.Linq
{
    public static class Enumerable
    {
        [Models.ExternalFunctionModels.EnableModel]
        public static TSource First<TSource>(this IEnumerable<TSource> source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (((CSharpCodeChecker_Kostil.HasItemObject<TSource>)source)._count <= 0)
                throw new InvalidOperationException(nameof(source));
            return ((CSharpCodeChecker_Kostil.HasItemObject<TSource>)source).Item;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public static TSource FirstOrDefault<TSource>(this IEnumerable<TSource> source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var src = (CSharpCodeChecker_Kostil.HasItemObject<TSource>)source;
            return src._count > 0 ? src.Item : default;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public static TSource Single<TSource>(this IEnumerable<TSource> source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var src = (CSharpCodeChecker_Kostil.HasItemObject<TSource>)source;
            if (src._count <= 0 || src._count > 1)
                throw new InvalidOperationException(nameof(source));
            return src.Item;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public static TSource SingleOrDefault<TSource>(this IEnumerable<TSource> source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var src = (CSharpCodeChecker_Kostil.HasItemObject<TSource>)source;
            if (src._count > 1)
                throw new InvalidOperationException(nameof(source));
            return src._count == 1 ? src.Item : default;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public static bool Any<TSource>(this IEnumerable<TSource> source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            return ((CSharpCodeChecker_Kostil.HasItemObject<TSource>) source)._count > 0;
        }

        public static bool Any<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (predicate == null)
                throw new ArgumentNullException(nameof(predicate));
            return ((CSharpCodeChecker_Kostil.HasItemObject<TSource>) source)._count > 0;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public static int Count<TSource>(this IEnumerable<TSource> source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            return ((CSharpCodeChecker_Kostil.HasItemObject<TSource>) source)._count;
        }
    }
}
