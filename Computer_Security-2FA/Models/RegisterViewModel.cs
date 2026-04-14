using System.ComponentModel.DataAnnotations;

namespace Computer_Security_2FA.Models
{
    public class RegisterViewModel
    {
        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
    }
}