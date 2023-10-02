namespace WebApi
{
    public static class GlobalDynamicSettings
    {
        //set this on program load
        public static string JwtToken_HashedSecnret { get; set; } //jwt secret key created dynamiclly on load. on every app restart, ***all pre created tokens consider as invalids***
        public static bool DebugMode_RunningLocal { get; set; } //set dynamic after init
        public static string EmailHashedPass { get; set; } //set after first init depend if local or production env
        public const int UserMinPassLength = 5;
    }
}