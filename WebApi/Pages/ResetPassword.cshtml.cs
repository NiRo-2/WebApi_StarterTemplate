using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using WebApi.Services;

namespace WebApi.Pages
{
    public class ResetPassword : PageModel
    {
        private readonly ILogger<ResetPassword> _logger;
        private readonly IPasswordResetTokenService _passwordResetTokenService;

        public ResetPassword(IPasswordResetTokenService passwordResetTokenService, ILogger<ResetPassword> logger)
        {
            _logger = logger;
            _passwordResetTokenService = passwordResetTokenService;
        }

        [BindProperty]
        public string NewPassword { get; set; } = "";

        [BindProperty]
        public string ConfirmPassword { get; set; } = "";

        public string ErrorMessage { get; set; } = "";
        public string SuccessMessage { get; set; } = "";
        public bool InvalidToken { get; set; } = false;

        public IActionResult OnGet()
        {
            // Get the token from the query string
            string? token = Request.Query["token"];

            if (string.IsNullOrEmpty(token))
            {
                // Handle the case where the token is missing or invalid
                ErrorMessage = "Invalid or missing reset password token.";
                InvalidToken = true;
                return Page();
            }

            //get token from base64
            token = NrExtras.StringsHelper.StringsHelper.FromBase64(token);

            //validate token
            // URL-decode the parameter to get the original string
            if (!_passwordResetTokenService.VerifyPasswordResetTokenAsync(NrExtras.EncryptionHelper.EncryptionHelper.DecryptKey(token)).Result)
            {
                ErrorMessage = "Invalid or expired reset password token.";
                InvalidToken = true;
                return Page();
            }

            //reset temp data on load before getting the page back
            TempData["NewPassword"] = null;
            TempData["ConfirmPassword"] = null;

            return Page();
        }

        //onPost - when user submitting new password. validating token, validating pass length and equal to confirmation pass and after all that, making password update
        public IActionResult OnPost()
        {
            Console.WriteLine("ResetPassword OnPost called");
            //get and validate token - URL-decode the parameter to get the original string
            string? token = Request.Query["token"];
            if (string.IsNullOrEmpty(token))
            {
                // Handle the case where the token is missing or invalid
                ErrorMessage = "Invalid or missing reset password token.";
                InvalidToken = true;
                return Page();
            }

            //get token from base64
            token = NrExtras.StringsHelper.StringsHelper.FromBase64(token);

            //save data in state so it will not lost one refresh
            TempData["NewPassword"] = NewPassword;
            TempData["ConfirmPassword"] = ConfirmPassword;

            //validate match passwords
            if (NewPassword != ConfirmPassword)
            {
                ErrorMessage = "Passwords do not match!";
                return Page();
            }

            //validate length
            if (NewPassword.Length < GlobalDynamicSettings.UserMinPassLength)
            {
                ErrorMessage = $"Password length must be at least {GlobalDynamicSettings.UserMinPassLength} characters.";
                return Page();
            }

            //Validate pass strength
            if (!Models.User.IsStrongPassword(NewPassword))
            {
                ErrorMessage = "Password must include at least one digit and one char";
                return Page();
            }

            try
            {
                // Validate the reset token
                if (!_passwordResetTokenService.VerifyPasswordResetTokenAsync(NrExtras.EncryptionHelper.EncryptionHelper.DecryptKey(token)).Result)
                {
                    ErrorMessage = "Invalid or expired reset password token.";
                    InvalidToken = true;
                    return Page();
                }

                // Call the UsersController to handle the password reset
                bool resetPasswordResult = CallResetPasswordEndpointAsync(NrExtras.EncryptionHelper.EncryptionHelper.DecryptKey(token), NewPassword).Result;

                if (resetPasswordResult) // Password reset successful
                    SuccessMessage = "Password reset successful.";
                else // Password reset failed
                    ErrorMessage = "An error occurred while resetting the password.";

                //reset values at the end
                TempData["NewPassword"] = null;
                TempData["ConfirmPassword"] = null;
                return Page();
            }
            catch (Exception ex)
            {
                // Log the exception
                _logger.LogError(ex, "An error occurred while resetting the password.");
                ErrorMessage = "An error occurred while processing your request.";
                return Page();
            }
        }

        /// <summary>
        /// Calling reset password api
        /// </summary>
        /// <param name="token">token</param>
        /// <param name="newPassword">new password</param>
        /// <returns>true if all good, false otherwise</returns>
        private async Task<bool> CallResetPasswordEndpointAsync(string token, string newPassword)
        {
            //get email out of token
            string email = await _passwordResetTokenService.ExtractEmailFromToken(token);
            //if don't have email - we have a problem
            if (string.IsNullOrEmpty(email))
                return false;

            using (var httpClient = new HttpClient())
            {
                //get reset password end point
                string endpointUrl = $"{Request.Scheme}://{Request.Host}/api/users/reset-password";

                // Create a JSON payload with the required data
                var payload = new
                {
                    Email = email,
                    Token = token,
                    NewPassword = newPassword
                };

                // Serialize the payload to JSON
                var jsonPayload = Newtonsoft.Json.JsonConvert.SerializeObject(payload);

                // Create a StringContent with the JSON payload
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                // Send the HTTP POST request
                var response = await httpClient.PostAsync(endpointUrl, content);

                // Check the response status code
                if (response.IsSuccessStatusCode)
                {
                    // The password reset was successful
                    return true;
                }
                else
                {
                    // The password reset failed
                    return false;
                }
            }
        }
    }
}