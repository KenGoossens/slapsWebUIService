using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;


namespace GetModernKeyVaultAADAuth.Models
{
    public class MyKeyVaultModel
    {
        [Display(Name = "KeyVault")]
        public string keyvault { get; set; }
        [Display(Name = "Hostname")]
        public string Hostname { get; set; }
    }
}
