using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Mvc;
using omco.erp.web;
using omco.erp.web.Models;
using omco.erp.web.Services;
using Novell.Directory.Ldap;
using System.Security.Cryptography;
using System.Text;

namespace omco.erp.web.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        //
        // GET: /Account/Index
        [HttpGet]
        public async Task<IActionResult> Index(ManageMessageId? message = null)
        {
            ViewData["StatusMessage"] =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.SetTwoFactorSuccess ? "Your two-factor authentication provider has been set."
                : message == ManageMessageId.Error ? "An error has occurred."
                : message == ManageMessageId.AddPhoneSuccess ? "Your phone number was added."
                : message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed."
                : "";

            var model = new IndexViewModel
            {
            };
            return View(model);
        }



        //
        // GET: /Account/AddPhoneNumber
        public IActionResult AddPhoneNumber()
        {
            return View();
        }
        //
        // GET: /Manage/ChangeMail
        [HttpGet]
        public IActionResult ChangeMail()
        {
            var entry = FindSingleEntry(string.Format("uid={0},ou=people,dc=tuleap,dc=local", User.GetUserId()), string.Empty);
            if(entry == null)
            {
                ModelState.AddModelError(string.Empty, "系统发生异常或者您的用户数据已被删除，请联系管理人员");
                return View();
            }
            var oldMail = entry.getAttribute("mail").StringValue;
            var model = new ChangeMailViewModel
            {
                OldMail = oldMail
            };
            return View(model);
        }

        //
        // POST: /Account/Manage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangeMail(ChangeMailViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var uid = User.GetUserId();
            if(model.NewEmail == model.OldMail)
            {
                ModelState.AddModelError(string.Empty, "新邮箱不能和旧邮箱重复");
                return View();
            }
            var entries = FindEntry("ou=people,dc=tuleap,dc=local", string.Format("mail={0}", model.NewEmail));
            var entry = entries.FirstOrDefault();
            if (entry != null && entry.DN != string.Format("uid={0},ou=people,dc=tuleap,dc=local", uid))
            {
                ModelState.AddModelError(string.Empty, "邮箱地址已存在");
                return View();
            }
            ChangeMail(uid, model.NewEmail);
            return RedirectToAction(nameof(Index), new { Message = "邮箱修改成功" });
        }

        //
        // GET: /Manage/ChangePassword
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        //
        // POST: /Account/Manage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            if(model.NewPassword == model.OldPassword)
            {
                ModelState.AddModelError(string.Empty, "新旧密码不能重复");
                return View();
            }
            var uid = User.GetUserId();
            var checkResult = CheckPassword(uid, model.OldPassword);
            if (checkResult.Succeeded)
            {
                ChangePassword(uid, model.NewPassword);
            }
            else
            {                 
                return View();
            }
            return RedirectToAction(nameof(Index), new { Message = "密码修改成功" });
        }

        //
        // GET: /Manage/SetPassword
        [HttpGet]
        public IActionResult SetPassword()
        {
            return View();
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        public enum ManageMessageId
        {
            AddPhoneSuccess,
            AddLoginSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), nameof(HomeController));
            }
        }

        #endregion

        #region

        private SignInResult ChangePassword(string uid,string newPassword)
        {
            LdapConnection ldapConn = new LdapConnection();
            ldapConn.Connect("120.26.214.254", 389);
            ldapConn.Bind("cn=Manager,dc=tuleap,dc=local", "123456");
            LdapAttribute attr = new LdapAttribute("userPassword", ToMd5(newPassword));
            LdapModification mod = new LdapModification(LdapModification.REPLACE, attr);
            ldapConn.Modify(string.Format("uid={0},ou=people,dc=tuleap,dc=local", uid), mod);
            ldapConn.Disconnect();
            return SignInResult.Success;
        }

        private SignInResult ChangeMail(string uid, string newEmail)
        {
            LdapConnection ldapConn = new LdapConnection();
            ldapConn.Connect("120.26.214.254", 389);
            ldapConn.Bind("cn=Manager,dc=tuleap,dc=local", "123456");
            LdapAttribute attr = new LdapAttribute("mail", newEmail);
            LdapModification mod = new LdapModification(LdapModification.REPLACE, attr);
            ldapConn.Modify(string.Format("uid={0},ou=people,dc=tuleap,dc=local", uid), mod);
            ldapConn.Disconnect();
            return SignInResult.Success;
        }

        private string ToMd5(string input)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            return "{MD5}" + Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(input.Trim())));
        }

        private SignInResult CheckPassword(string uid, string password)
        {
            var entry = FindSingleEntry(string.Format("uid={0},ou=people,dc=tuleap,dc=local", uid), string.Empty);
            if (entry == null)
            {
                ModelState.AddModelError(string.Empty, "工号不存在");
                return SignInResult.Failed;
            }
            var attr = entry.getAttribute("userPassword");
            var ldapPassword = attr.StringValue;
            var userPassword = ToMd5(password);
            if (ldapPassword == userPassword || ldapPassword == password)
            {
                return SignInResult.Success;
            }
            else
            {
                ModelState.AddModelError(string.Empty, "旧密码不正确");
            }
            return SignInResult.Failed;

        }


        private LdapEntry FindSingleEntry(string searchBase, string filter)
        {
            LdapConnection ldapConn = new LdapConnection();
            ldapConn.Connect("120.26.214.254", 389);
            ldapConn.Bind("cn=Manager,dc=tuleap,dc=local", "123456");
            var lsc = ldapConn.Search(searchBase, LdapConnection.SCOPE_BASE, filter, null, false);
            LdapEntry nextEntry = null;
            while (lsc.hasMore())
            {
                nextEntry = lsc.next();
                break;
            }
            ldapConn.Disconnect();
            return nextEntry;
        }


        private IEnumerable<LdapEntry> FindEntry(string searchBase, string filter)
        {
            LdapConnection ldapConn = new LdapConnection();
            ldapConn.Connect("120.26.214.254", 389);
            ldapConn.Bind("cn=Manager,dc=tuleap,dc=local", "123456");
            var lsc = ldapConn.Search(searchBase, LdapConnection.SCOPE_SUB, filter, null, false);
            LdapEntry nextEntry = null;
            while (lsc.hasMore())
            {
                nextEntry = lsc.next();
                yield return nextEntry;
            }
            ldapConn.Disconnect();
        }
        #endregion
    }
}
