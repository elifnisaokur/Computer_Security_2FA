using System.ComponentModel.DataAnnotations;

namespace Computer_Security_2FA.Models
{
    public class Verify2FAViewModel
    {
        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        [StringLength(6, MinimumLength = 6)]
        public string Code { get; set; } = string.Empty;

        public bool RememberDevice { get; set; }
    }
}
