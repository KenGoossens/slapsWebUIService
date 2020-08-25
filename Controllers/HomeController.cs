using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using GetModernKeyVaultAADAuth.Models;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;
using System.Security.Claims;
using Microsoft.Graph;
using System.IO;
using Microsoft.Identity.Client;
using GetModernKeyVaultAADAuth.Infra;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;

namespace GetModernKeyVaultAADAuth.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private string Message { get; set; }
        private HashSet<SecretItem> Secrets { get; set; }
        public string Keyvault { get; set; }


        private Claim WebappClaim { get; set; }
        private Claim UpnClaim { get; set; }

        private readonly ITokenAcquisition tokenAcquisition;
        private readonly WebOptions webOptions;
        private readonly TelemetryConfiguration config = TelemetryConfiguration.CreateDefault();

        private TelemetryClient Telemetry { get; set; }

        public HomeController(ITokenAcquisition tokenAcquisition, IOptions<WebOptions> webOptionValue, ILogger<HomeController> logger)
        {
            this.tokenAcquisition = tokenAcquisition;
            this.webOptions = webOptionValue.Value;
            Secrets = new HashSet<SecretItem>();
            // !!!!! specify your keyvault name
            Keyvault = "";
            // !!!!! add your azure ad group ID between the "" at the end
            WebappClaim = new Claim("groups", "");
            // Not required
            UpnClaim = new Claim("name", "");
            Telemetry = new TelemetryClient(config);
        }

        [AuthorizeForScopes(Scopes = new[] { Infra.Constants.ScopeUserRead })]
        public async Task<IActionResult> Profile()
        {
            // Initialize the GraphServiceClient. 
            try
            {
                //Get client to call user endpoint
                GraphServiceClient graphClient = GetGraphServiceClient(new[] { Infra.Constants.ScopeUserRead });
                //Make call to Graph API to get the current users profile. This works because the client has the authorization key of the user
                var me = await graphClient.Me.Request().GetAsync();
                ViewData["Me"] = me;

                // Get user photo and convert it to a base 64 string which can then be sent to view to be shown as base64
                using var photoStream = await graphClient.Me.Photo.Content.Request().GetAsync();
                byte[] photoByte = ((MemoryStream)photoStream).ToArray();
                ViewData["Photo"] = Convert.ToBase64String(photoByte);
            }
            catch (MsalUiRequiredException e)
            {
                ViewData["Photo"] = null;
                throw e;
            }
            catch (System.Exception e)
            {

                ViewData["Photo"] = null;
                throw e;
            }


            return View();
        }

        private GraphServiceClient GetGraphServiceClient(string[] scopes)
        {
            //Ask the Graph Factoy to create a GraphServiceAPI client. Using the token of the user that is logged in authorized
            return GraphFactory.GetAuthenticatedGraphClient(async () =>
            {
                //Uses project Microsoft.Identity.Web to get the token
                string result = await tokenAcquisition.GetAccessTokenForUserAsync(scopes);
                return result;
            }, webOptions.GraphApiUrl);
        }

        public async Task OnGetAsync(string identifier, string keyvaultname)
        {
            try
            {
                /* The next four lines of code show you how to use AppAuthentication library to fetch secrets from your key vault */
                //Connect to Azure and get token for Managed Account and use that token to connect to AKV and fetch secret
                AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
                KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
                var secret = await keyVaultClient.GetSecretAsync(String.Format("https://{0}.vault.azure.net/secrets/{1}",keyvaultname, identifier)).ConfigureAwait(false);
                Message += secret.Value;

            }
            /* If you have throttling errors see this tutorial https://docs.microsoft.com/azure/key-vault/tutorial-net-create-vault-azure-web-app */
            /// <exception cref="KeyVaultErrorException">
            /// Thrown when the operation returned an invalid status code
            /// </exception>
            catch (KeyVaultErrorException keyVaultException)
            {
                Message = keyVaultException.Message;
            }
            catch (Exception e)
            {
                Message = e.Message;
            }
        }

        public async Task OnGetListAsync(string identifier)
        {
            try
            {
                /* The next four lines of code show you how to use AppAuthentication library to fetch secrets from your key vault */
                AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
                KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
                var secret = await keyVaultClient.GetSecretsAsync(String.Format("https://{0}.vault.azure.net", identifier)).ConfigureAwait(false);
                Secrets = secret.ToHashSet() ;

            }
            /* If you have throttling errors see this tutorial https://docs.microsoft.com/azure/key-vault/tutorial-net-create-vault-azure-web-app */
            /// <exception cref="KeyVaultErrorException">
            /// Thrown when the operation returned an invalid status code
            /// </exception>
            catch (KeyVaultErrorException keyVaultException)
            {
                Message = keyVaultException.Message;
                Telemetry.TrackEvent(String.Format("Could not reach vault. Exception: {0}", keyVaultException.Message));

            }
            catch (Exception e)
            {
                Message = e.Message;
                Telemetry.TrackEvent(String.Format("General exception when reaching vault. Exception: {0}", e.Message));
            }
        }

        public int GetClaimCount(Func<Claim, bool> filter)
        {
            //Get the current logged in user
            var userClaims = ((ClaimsIdentity)User.Identity).Claims;
            //Count returns the number of claims that match the filter. We check here whether the user is in a specific group to allow him access.
            return userClaims.Count(filter);

        }

        public string GetClaimValue(Func<Claim, bool> filter)
        {
            var userClaims = ((ClaimsIdentity)User.Identity).Claims;
            //This filter is used to get the username, can be used to get any claim
            return userClaims.FirstOrDefault(filter) == null ? "Not Found" : userClaims.FirstOrDefault(filter).Value;

        }

        private Func<Claim, bool> CreateFunction(Claim webappClaim, bool filterOnValue)
        {
            //Filter either on type only (to get his name for example) or on type and value (check if he's in a certain group for example)
            if (filterOnValue) {
                 return cl => (cl.Type == webappClaim.Type && cl.Value == webappClaim.Value);
            }
            else
            {
                return cl => (cl.Type == webappClaim.Type);
            }
           
        }

        public void SetDefaultValuesUnAuthorized()
        {
            //By default: no access.
            ViewData["keyvault"] = "";
            ViewData["secrets"] = Secrets;
            ViewData["hasaccess"] = false;
        }

        private void SetDefaultValuesAuthorized(Dictionary<string,string> valuePairs)
        {
            //Fetch user info, setup some values and pass any other key-values to the front end
            //Profile().Wait();
            ViewData["keyvault"] = Keyvault;
            ViewData["hasaccess"] = true;
            OnGetListAsync(Keyvault).Wait();
            ViewData["secrets"] = Secrets;
            var upnValue = GetClaimValue(CreateFunction(UpnClaim, false));
            
            //Fetch the tenant here (or anythin else based on upnclaim)
            ViewData["tenantname"] = upnValue.Substring(upnValue.LastIndexOf("@")+1);
            foreach (var item in valuePairs)
            {
                ViewData[item.Key] = item.Value;
            }
        }

        public IActionResult Index()
        {
            SetDefaultValuesUnAuthorized();
            //check if he is in group, if so show search bar etc.
            if (GetClaimCount(CreateFunction(WebappClaim, true)) > 0)
            {
                SetDefaultValuesAuthorized(new Dictionary<string, string>());
            }

            return View();
        }

        public IActionResult Search([Bind("Hostname")] MyKeyVaultModel model)
        {
            ModelState.Clear();
            SetDefaultValuesUnAuthorized();

            if (GetClaimCount(CreateFunction(WebappClaim, true)) > 0)
            {
                Telemetry.TrackEvent(String.Format("Search for Hostname {0} made by {1}", model.Hostname, GetClaimValue(CreateFunction(UpnClaim, false))));
                Telemetry.Flush();
                //Fetch list of secrets and pass the names to the front end. This is in plain text. If you want this more secure, you could check the names here instead of client side validation in JS.
                OnGetAsync(model.Hostname, Keyvault).Wait();
                var dictionary2 = new Dictionary<string, string>() {
                    { "Hostname", model.Hostname }, { "Message", Message }
                };
                SetDefaultValuesAuthorized(dictionary2);
            }

            return View("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}