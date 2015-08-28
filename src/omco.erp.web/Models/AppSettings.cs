using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace omco.erp.web.Models
{
    public class AppSettings
    {
        public string SiteTitle { get; set; }
        public string LdapHost { get; set; }
        public int LdapPort { get; set; }
        public string LdapManagerDN { get; set; }
        public string LdapManagerPwd { get; set; }
        public string LdapPeopleOU { get; set; }
    }
}
