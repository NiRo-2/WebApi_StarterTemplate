using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Please Enter Email")]
        [EmailAddress]
        public string email { get; set; }

        [Required(ErrorMessage = "Please Enter Password")]
        [DataType(DataType.Password)]
        public string password { get; set; }
    }
}