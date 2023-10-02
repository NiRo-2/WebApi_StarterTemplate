using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}