using System;

namespace CSharpCodeChecker_Kostil
{
    public abstract class HasItemObject<T>
    {
        [Models.ExternalFunctionModels.EnableModel]
        protected int _getRandom()
        {
            return (new Random()).Next() % _count;
        }
        [Models.ExternalFunctionModels.EnableModel]
        private T _item;
        [Models.ExternalFunctionModels.EnableModel]
        internal T Item
        {
            [Models.ExternalFunctionModels.EnableModel]
            get { return _item; }
            [Models.ExternalFunctionModels.EnableModel]
            set { _item = _getRandom() == 0 ? value : _item; }
        }

        internal int _count;
    }

    internal static class AnyConverter
    {    
        internal static TResult Convert<TSource,TResult>(TSource item) 
            => (TResult)((object)item);
    }
}

public class @object
{
    public virtual string ToString() => ((object)this) as string ?? GetType().Name;
}

namespace Models.ExternalFunctionModels
{
    internal class EnableModelAttribute : Attribute
    {
    }
}
