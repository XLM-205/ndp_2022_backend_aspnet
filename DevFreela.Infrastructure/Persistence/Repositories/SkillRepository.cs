using Dapper;
using DevFreela.Core.DTOs;
using DevFreela.Core.Repositories;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace DevFreela.Infrastructure.Persistence.Repositories
{
    public class SkillRepository : ISkillRepository
    {
        private readonly string _connectionString;
        private readonly DevFreelaDbContext _dbContext;
        public SkillRepository(DevFreelaDbContext dbContext, IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DevFreelaCs");
            _dbContext = dbContext;
        }

        public async Task<List<SkillDTO>> GetAllAsync()
        {
            //using (var sqlConnection = new SqlConnection(_connectionString))
            //{
            //    sqlConnection.Open();

            //    var script = "SELECT Id, Description FROM Skills";

            //    var skills = await sqlConnection.QueryAsync<SkillDTO>(script);

            //    return skills.ToList();
            //}

            // COM EF CORE
            var skills = _dbContext.Skills;

            var skillsViewModel = skills
                .Select(s => new SkillDTO { Id = s.Id, Description = s.Description })
                .ToList();

            return skillsViewModel;
        }
    }
}
