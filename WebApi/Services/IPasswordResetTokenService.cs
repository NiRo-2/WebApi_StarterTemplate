using System;
using System.Threading.Tasks;

namespace WebApi.Services
{
    public interface IPasswordResetTokenService
    {
        Task CreatePasswordResetTokenAsync(string userId, string token, DateTime expiration);
        Task<bool> VerifyPasswordResetTokenAsync(string userId, string token);
        Task<bool> VerifyPasswordResetTokenAsync(string token);
        Task MarkTokenAsUsedAsync(string userId, string token);
        Task RemoveExpiredTokensAsync();
        Task<string> ExtractEmailFromToken(string token);
    }
}