using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Configuration;

namespace WebApi.Models
{
    public class ResetPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Token { get; set; }

        [Required(ErrorMessage = "Invalid password")]
        [MinLength(GlobalDynamicSettings.UserMinPassLength, ErrorMessage = "Invalid password legnth")]
        public string NewPassword { get; set; }
    }
}