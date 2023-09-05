using Microsoft.EntityFrameworkCore;
using NrExtras.Logger;
using WebApi.Models;

namespace WebApi
{
    /// <summary>
    /// User service for user-related operations
    /// </summary>
    public class UserService
    {
        private readonly AppDbContext _context;

        public UserService(AppDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Get user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns>Found user or null</returns>
        public async Task<User?> GetUserByEmailAsync(string email)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                return user;
            }
            catch (Exception ex)
            {
                Logger.WriteToLog(ex);
                return null;
            }
        }

        /// <summary>
        /// Update user email confirmation as confirmed
        /// </summary>
        /// <param name="email">email address</param>
        /// <returns>true on success, false otherwise</returns>
        public async Task<bool> UpdateUserEmailConfirmationStatusAsync(string email)
        {
            try
            {
                var user = await GetUserByEmailAsync(email);
                if (user != null)
                {
                    user.EmailConfirmed = 1;
                    await _context.SaveChangesAsync();
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.WriteToLog(ex);
                return false;
            }
        }
    }
}