namespace WebApi
{
    public static class GlobalDynamicSettings
    {
        //set this on program load
        public static string JwtToken_HashedSecnret { get; set; } //jwt secret key created dynamiclly on load. on every app restart, ***all pre created tokens consider as invalids***
        //public static string JwtEncryptionKey_Hashed { get; set; } //jwt encryption key created dynamiclly on load. on every app restart, ***all pre created tokens consider as invalids***
        public static bool DebugMode_RunningLocal { get; set; }
        public static string EmailHashedPass { get; set; }
        public const int UserMinPassLength  = 5;
    }
}