using System.ComponentModel.DataAnnotations;

namespace AuthorizationServer.Api.Models
{
    public class AudienceModel
    {
        [MaxLength(100)]
        [Required]
        public string Name { get; set; }
    }
}