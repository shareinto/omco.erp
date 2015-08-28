using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Mvc.Rendering;
using Microsoft.Data.Entity;
using omco.erp.web;
using omco.erp.web.Models;
using omco.erp.web.Services;
using Novell.Directory.Ldap;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Framework.OptionsModel;
using omco.erp.web.Utils;

namespace omco.erp.web.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private IOptions<AppSettings> settings;
        public AccountController(IOptions<AppSettings> settings)
        {
            this.settings = settings;
        }
        //
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {             
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var result = SignIn(model.Uid, model.Password);
                if(result.Succeeded)
                {
                    if (!string.IsNullOrEmpty(returnUrl))
                    {
                        RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }
                }
            }
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LogOff()
        {
            Context.Authentication.SignOut();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        // GET: /Account/ConfirmEmail
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            return View();
        }

        //
        // GET: /Account/ForgotPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
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

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        private SignInResult SignIn(string uid, string password)
        {
            using (Ldap ldap = new Ldap(settings.Options.LdapHost, settings.Options.LdapPort))
            {
                ldap.Bind(settings.Options.LdapManagerDN, settings.Options.LdapManagerPwd);
                var entry = ldap.SearchOne(settings.Options.LdapPeopleOU, LdapScope.ONE, string.Format("uid={0}", uid));
                if (entry == null)
                {
                    ModelState.AddModelError(string.Empty, "工号不存在");
                    return SignInResult.Failed;
                }
                try
                {
                    ldap.Bind(entry.DN, password);
                }
                catch
                {
                    ModelState.AddModelError(string.Empty, "密码不正确");
                    return SignInResult.Failed;
                }
                var name = entry.getAttribute("cn") == null ? string.Empty : entry.getAttribute("cn").StringValue;
                var mail = entry.getAttribute("mail") == null ? string.Empty : entry.getAttribute("cn").StringValue;
                var identity = new ClaimsIdentity(IdentityOptions.ApplicationCookieAuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, name));
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, uid));
                identity.AddClaim(new Claim(ClaimTypes.Email, mail));
                Context.Authentication.SignIn(string.Empty, new ClaimsPrincipal(identity));
                return SignInResult.Success;
            }
        }
        #endregion
    }
}
