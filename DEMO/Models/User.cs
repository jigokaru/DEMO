using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace DEMO.Models
{
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int userId { get; set; }
        [Required(ErrorMessage ="NickName is required")]
        [MaxLength(30, ErrorMessage = "NickName has a maximum of 30 characters")]
        public string nickName { get; set; } = string.Empty;
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string email { get; set; } = string.Empty;
        [Required(ErrorMessage = "Passord is required")]
        [MinLength(6,ErrorMessage = "Password must have at least 6 characters")]
        public string password { get; set; } = string.Empty;
        public string userRole { get; set; } = "ADMIN";
        public bool IsActive { get; set; } = true;
        public DateTime createAt {  get; set; }

    }
}
