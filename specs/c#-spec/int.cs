using System;
public struct @int
{
    public static bool TryParse(string s, out int result)
    {
        if (string.IsNullOrEmpty(s))
        {
            result = 0;
            return false;
        }
        result = CSharpCodeChecker_Kostil.AnyConverter.Convert<string, int>(s);
        return true;
    }
}
