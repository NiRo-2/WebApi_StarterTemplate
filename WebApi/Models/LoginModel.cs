using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Please Enter Email")]
        [EmailAddress]
        public string email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please Enter Password")]
        [DataType(DataType.Password)]
        public string password { get; set; } = string.Empty;
        public string? recaptchaToken_v3 { get; set; } // Optional reCAPTCHA v3 token, can be null if reCAPTCHA is not enabled
    }
}