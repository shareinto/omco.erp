using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace omco.erp.web.Utils
{
    public class Ldap : IDisposable
    {
        private LdapConnection connection = new LdapConnection();
        public Ldap(string host, int port)
        {
            connection.Connect(host, port);
        }

        public void Bind(string dn,string pwd)
        {
            connection.Bind(dn, pwd);
        }

        public LdapEntry SearchOne(string searchBase, LdapScope scope, string filter)
        {
            var lsc = connection.Search(searchBase, (int)scope, filter, null, false);
            LdapEntry result = null;
            while (lsc.hasMore())
            {
                result = lsc.next();
                break;
            }
            return result;
        }

        public IEnumerable<LdapEntry> Search(string searchBase, LdapScope scope,string filter)
        {
            var lsc = connection.Search(searchBase, (int)scope, filter, null, false);
            while (lsc.hasMore())
            {
                yield return lsc.next();
            }
        }
        public void Modify(string dn, LdapModification mod)
        {
            connection.Modify(dn, mod);
        }

        public void Dispose()
        {
            if(connection.Connected)
            {
                connection.Disconnect();
            }
        }
    }

    public enum LdapScope
    {
        BASE = 0,
        ONE = 1,
        SUB = 2
    }
}
