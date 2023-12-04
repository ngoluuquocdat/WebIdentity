using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using Web2FA.Data.Entities;

namespace Web2FA.Data.Utils
{
    public static class DatabaseInitiation
    {
        public static void Execute(WebApplication app)
        {
            var scope = app.Services.CreateScope();
            var _dbContext = scope.ServiceProvider.GetService<MyDbContext>();
            if( _dbContext == null )
            {
                Console.WriteLine("Cannot init in-memory database");
                return;
            }
            var accounts = new List<Account>
            {
                new Account
                {
                   Id = Guid.NewGuid(), 
                   Name = "Peter",
                   Email = "peter@gmail.com",
                   Password = "pass@123"
                },
                new Account
                {
                   Id = Guid.NewGuid(),
                   Name = "Drew",
                   Email = "drew@enclave.com",
                   Password = "pass@123"
                },
            };

            var identityUsers = new List<IdentityUser>
            {
                new IdentityUser
                {
                    UserName = "Drew Ngo",
                    Email = "drew@enclave.com"
                }
            };
            _dbContext.Accounts.AddRange(accounts);
            _dbContext.SaveChanges();
        }
    }
}
