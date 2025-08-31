namespace WebApi.Models
{
    /// <summary>
    /// Configuration class for JWT (JSON Web Token) settings.
    /// </summary>
    public sealed class JwtConfig
    {
        public string JwtCookieName { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string Audience { get; set; } = "";
        public int TokenExpirationHours { get; set; }
        public int EmailVerificationTokenExpirationHours { get; set; }
        public int PasswordResetTokenExpirationMinutes { get; set; }
    }
}