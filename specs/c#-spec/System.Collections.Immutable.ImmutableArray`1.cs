using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Collections.Immutable
{
    public static class ImmutableArray
    {
        [Models.ExternalFunctionModels.EnableModel]
        public static ImmutableArray<T> Create<T>() => new ImmutableArray<T>(0);
        

        [Models.ExternalFunctionModels.EnableModel]
        public static ImmutableArray<T> Create<T>(T item) => new ImmutableArray<T>(1);


        [Models.ExternalFunctionModels.EnableModel]
        public static ImmutableArray<T> Create<T>(T item1, T item2) => new ImmutableArray<T>(2);

        [Models.ExternalFunctionModels.EnableModel]
        public static ImmutableArray<T> Create<T>(T item1, T item2, T item3) => new ImmutableArray<T>(3);

        [Models.ExternalFunctionModels.EnableModel]
        public static ImmutableArray<T> Create<T>(T item1, T item2, T item3, T item4) => new ImmutableArray<T>(4);

        
        //items.Length is AnonVid
        public static ImmutableArray<T> Create<T>(params T[]? items) => new ImmutableArray<T>(items.Length);
    }

    public readonly struct ImmutableArray<T>
    {
        [Models.ExternalFunctionModels.EnableModel]
        public readonly int length;

        [Models.ExternalFunctionModels.EnableModel]
        public ImmutableArray(int length)
        {
            this.length = length;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public int Length { [Models.ExternalFunctionModels.EnableModel] get => length; }

        [Models.ExternalFunctionModels.EnableModel]
        public ImmutableArray<T> Add(T item) => new ImmutableArray<T>(Length + 1);

    }
}
