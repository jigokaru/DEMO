using DEMO.Models;
using Microsoft.EntityFrameworkCore;

namespace DEMO.Services
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {
            
        }

        public DbSet<User> User { get; set; }
        public DbSet<Tokens> Tokens { get; set; }
    }
}
