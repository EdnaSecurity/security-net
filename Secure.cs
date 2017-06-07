using System;
using System.Configuration;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Reflection;
using CircuitBreaker.Net.Exceptions;
using System.Net;

namespace Edna
{
    public class Secure : IHttpModule
    {
        // E-DNA secret key
        protected static string _secretkey;

        // E-DNA public key
        protected static string _publickey;

        // E-DNA API endpoint
        protected static string _uri;

        // Auth HTTP username
        protected static string _username;

        // Auth HTTP password
        protected static string _password;

        // API Requests timeout
        protected static int _timeout;

        // Turn on/off the debug mode
        private static bool _debug_mode;

        // This property replace the origin from the dashboard
        private static string _security_mode;

        // This property will allow the module to redirect to an extern URI as a security concern
        private static bool _autoRedirection;

        // Breaker reset timeout
        private static int _breaker_reset_timeout;

        // Breaker invoation time timeout
        private static int _breaker_invoc_timeout;

        // Fails breaker times
        private static int _breaker_max_failures;

        // The proxy options for the client
        private static string _proxy_address = null;

        // Results of the request call
        protected string _results;

        static Secure()
        {
            AppDomain.CurrentDomain.AssemblyResolve += Edna_Assembly_Modules;
            _secretkey = ConfigurationManager.AppSettings["_secretkey"];
            _publickey = ConfigurationManager.AppSettings["_publickey"];
            _uri = ConfigurationManager.AppSettings["_uri"];
            _username = ConfigurationManager.AppSettings["_username"];
            _password = ConfigurationManager.AppSettings["_password"];
            _timeout = Int32.Parse(ConfigurationManager.AppSettings["_timeout"]);
            _debug_mode = Boolean.Parse(ConfigurationManager.AppSettings["_debug_mode"]);
            _security_mode = ConfigurationManager.AppSettings["_security_mode"];
            _autoRedirection = Boolean.Parse(ConfigurationManager.AppSettings["_autoRedirection"]);
            _breaker_reset_timeout = Int32.Parse(ConfigurationManager.AppSettings["_breaker_reset_timeout"]);
            _breaker_invoc_timeout = Int32.Parse(ConfigurationManager.AppSettings["_breaker_invoc_timeout"]);
            _breaker_max_failures = Int32.Parse(ConfigurationManager.AppSettings["_breaker_max_failures"]);
            _proxy_address = ConfigurationManager.AppSettings["_proxy_address"] ?? null;
        }

        // Register the CircuitBreaker module to assembly
        private static Assembly Edna_Assembly_Modules(object sender, ResolveEventArgs args)
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Edna.CircuitBreaker.Net.dll"))
            {
                byte[] Data = new byte[stream.Length];
                stream.Read(Data, 0, Data.Length);
                return Assembly.Load(Data);
            }
        }

        // Sends an Async request to E-DNA endpoint
        [DebuggerNonUserCode]
        private async Task sendAsync(Object source, EventArgs e)
        {
            try
            {
                string _cookie_name = "_allow"; // Cookie name

                // Init the context application
                HttpApplication application = (HttpApplication) source;
                HttpContext context = application.Context;

                // get the current time
                DateTime now = DateTime.Now;

                // create a new cookie
                HttpCookie _cookie = null;

                // set the website server name
                string _site = context.Request.ServerVariables["SERVER_NAME"];

                // split the site string
                String[] explodedSite = _site.Split('.');
                // build the site url and the schema value
                if (_site.Substring(0, 4) != "www." && explodedSite.Length == 2)
                {
                    _site = "www." + _site;
                }

                // set the default server schema
                string http = "http://";

                if (context.Request.ServerVariables["HTTPS"] == "ON")
                {
                    http = "https://";
                }

                // create the cookie of not exists else change value
                if (!context.Response.Cookies.AllKeys.Contains(_cookie_name))
                {
                    _cookie = new HttpCookie(_cookie_name);
                    _cookie.Value = "false";
                    _cookie.Expires = now.AddHours(1);
                }
                else
                {
                    _cookie.Value = context.Request.QueryString["_alssl"];
                    _cookie.Expires = now.AddHours(1);
                }

                // add the cookie to response
                context.Response.Cookies.Add(_cookie);

                if (string.IsNullOrEmpty(context.Request.ServerVariables["HTTP_HOST"]))
                {
                    return;
                }

                // Json serializer object
                var jsonSerializer = new System.Web.Script.Serialization.JavaScriptSerializer();

                // get all the server variables keys
                var serverVariables = context.Request.ServerVariables;

                String[] httpKeys = serverVariables.AllKeys;
                Dictionary<string, string> httpValues = new Dictionary<string, string>();

                for (int i = 0; i < httpKeys.Length; i++)
                {
                    httpValues[httpKeys[i]] = serverVariables[httpKeys[i]];
                }

                // prepare the data to send
                var values = new Dictionary<string, string>
                {
                       { "secret", _secretkey },
                       { "public", _publickey },
                       { "server", jsonSerializer.Serialize(httpValues) },
                       { "site", _site }
                };

                // Encode the variables into query
                var data = new FormUrlEncodedContent(values);

                // Create an Http handler
                HttpClientHandler HttpHandler = new HttpClientHandler();

                if ( ! String.IsNullOrEmpty(_proxy_address) )
                {
                    HttpHandler.Proxy = new WebProxy(_proxy_address, false);
                    HttpHandler.UseProxy = true;
                }

                // start the http async call
                using (HttpClient client = new HttpClient(HttpHandler))
                {
                    // set the httpclient configuration
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Format("{0}:{1}", _username, _password))));
                    client.Timeout = TimeSpan.FromMilliseconds(_timeout);

                    HttpResponseMessage response = await client.PostAsync(_uri, data);
                    HttpContent content = response.Content;
                    // get the results
                    string results = await content.ReadAsStringAsync();

                    // decode the json into an object
                    var json = jsonSerializer.DeserializeObject(results);

                    if (!string.IsNullOrEmpty((string)GetValue(json, "error")))
                    {
                        context.Response.Write((string)GetValue(json, "error"));
                    }

                    if (GetValue(json, "security").Equals("off"))
                    {
                        // future actions
                    }
                    else if (GetValue(json, "security").Equals("on"))
                    {
                        if ( GetValue(json, "mode").Equals("active") && _security_mode.Equals("active") )
                        {
                            // set up a redirection url
                            string redirectionUri = null;

                            if (GetValue(GetValue(json, "results"), "clean").Equals(false))
                            {
                                var settings = (object)GetValue(json, "settings");
                                string typeAction = (string)GetValue(GetValue(json, "results"), "type");

                                // lower case the typeAction
                                typeAction = typeAction.ToLower();

                                if (!String.IsNullOrEmpty(typeAction))
                                {
                                    string behavior = (string)GetValue(GetValue(settings, "actions"), typeAction);

                                    if (!context.Response.Cookies.AllKeys.Contains(_cookie_name) || _cookie.Value == "false")
                                    {
                                        if (behavior.Equals("captcha"))
                                        {
                                            redirectionUri = "https://dash.e-dna.co/captcha?redirect=" + http + _site + "&_al=true";
                                        }
                                        else
                                        {
                                            redirectionUri = "https://dash.e-dna.co/jail";
                                        }
                                    }
                                }
                            }
                            else if (GetValue(GetValue(json, "results"), "black").Equals(true))
                            {
                                redirectionUri = "https://dash.e-dna.co/jail";
                            }

                            // check if the redirection is set to true
                            if (_autoRedirection.Equals(true))
                            {
                                context.Response.Redirect(redirectionUri);
                            }
                        }
                    }
                }
            }
            catch (TimeoutException ex)
            {
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();
                    Debug.WriteLine(ex.ToString());
                    Debug.Unindent();
                    Debug.Flush();
                }
            }
            catch (TaskCanceledException ex)
            {
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();
                    Debug.WriteLine(ex.ToString());
                    Debug.Unindent();
                    Debug.Flush();
                }
            }
            catch (AggregateException ex)
            {
                // This may contain multiple exceptions, which you can iterate with a foreach
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();

                    foreach (var exception in ex.InnerExceptions)
                    {
                        Debug.WriteLine(exception.Message);
                    }

                    Debug.Unindent();
                    Debug.Flush();
                }
            }
            catch (Exception ex)
            {
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();
                    Debug.WriteLine(ex.ToString());
                    Debug.Unindent();
                    Debug.Flush();
                }
            }
        }

        // Parse a json object and find the right value
        private object GetValue(dynamic json, string key)
        {
            foreach (KeyValuePair<string, object> item in json)
            {
                if (item.Key == key)
                    return item.Value;
            }
            return "";
        }
        public async Task Execute(Object source, EventArgs e)
        {
            var CircuitBreaker = new CircuitBreaker.Net.CircuitBreaker(
                  TaskScheduler.Default,
                  maxFailures: 2,
                  invocationTimeout: TimeSpan.FromMilliseconds(_breaker_invoc_timeout),
                  circuitResetTimeout: TimeSpan.FromMilliseconds(_breaker_reset_timeout)
            );

            try
            {
                await CircuitBreaker.ExecuteAsync(new Func<Task>(async () => await sendAsync(source, e)));
            }
            catch (CircuitBreakerOpenException)
            {
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();
                    Debug.WriteLine("CircuitBreakerOpenException");
                    Debug.Unindent();
                    Debug.Flush();
                }
            }
            catch (CircuitBreakerTimeoutException)
            {
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();
                    Debug.WriteLine("CircuitBreakerTimeoutException");
                    Debug.Unindent();
                    Debug.Flush();
                }
            }
            catch (Exception)
            {
                if (_debug_mode.Equals(true))
                {
                    Debug.WriteLine("E-DNA Exception: ");
                    Debug.Indent();
                    Debug.WriteLine("Exception");
                    Debug.Unindent();
                    Debug.Flush();
                }
            }
        }
        public void Init(HttpApplication context)
        {
            // Create a new Circuit breaker
            //var CircuitBreaker = new CircuitBreaker.Net.CircuitBreaker(
            //    TaskScheduler.Default,
            //    maxFailures: _breaker_max_failures,
            //    invocationTimeout: TimeSpan.FromMilliseconds(_breaker_invoc_timeout),
            //    circuitResetTimeout: TimeSpan.FromMilliseconds(_breaker_reset_timeout)
            //);
            // It wraps the Task-based method
            EventHandlerTaskAsyncHelper asyncHelper = new EventHandlerTaskAsyncHelper(Execute);

            //asyncHelper's BeginEventHandler and EndEventHandler eventhandler that is used
            //as Begin and End methods for Asynchronous HTTP modules
            context.AddOnPostAuthorizeRequestAsync(asyncHelper.BeginEventHandler, asyncHelper.EndEventHandler);
        }

        public void Dispose()
        {
            
        }
    }
}
