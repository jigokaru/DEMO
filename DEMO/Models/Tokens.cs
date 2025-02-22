using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace DEMO.Models
{
    public class Tokens
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int? Id { get; set; }
        public string? stoken { get; set; }
        private DateTime? _expiresAt = DateTime.Now.AddSeconds(10);
        public DateTime? expiresAt
        {
            get { return _expiresAt; }
            set
            {
                _expiresAt = value;
                if (_expiresAt.HasValue)
                {
                    if (_expiresAt.Value < DateTime.Now)
                    {
                        expired = true;
                        revoked = true;
                    }
                    else
                    {
                        expired = false;
                        revoked = false;
                        Task.Run(async () =>
                        {
                            await Task.Delay((_expiresAt.Value - DateTime.Now));
                            expired = true;
                            revoked = true;
                        });
                    }
                }
                else
                {
                    expired = false;
                    revoked = false;
                }
            }
        }


        public bool? expired { get; private set; }

        public bool? revoked { get; private set; }

        public string? token_type { get; set; }
        [ForeignKey("User")]
        public int userId { get; set; }
        public User User { get; set; } = null!;
    }
}
