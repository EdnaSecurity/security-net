# Getting started

This integration guide is a crisp and precise guide that will facilitate the integration of E-DNA - Anti-Scraping & Bot Prevention Solution at the application level using our `ASP.Net` cloud connector.

## Requirements

```javascript
.Net Framework version >= 4.0

Dependencies to be included before using the connector:
1. Newtonsoft JSON serialize library.
```

# Integration

When integrating our module every request is then parsed by our API asynchronously, if the request has been detected as a BOT, Proxy or a Scrapper eDNA will respond based on your settings (i.e Captcha, Blacklist) 
In the event that you disconnect eDNA from the dashboard UI, eDNA will not be able to establish the behaviour type of each request and classify the given request.  
Monitor mode (Passive) will save each request with all its behavioural analytics and classify each request however this will merely flag each request and no appropriate action will be taken.  
Selecting ‘Active’ mode all detected bad requests will be blocked alongside any other requests in real time. 

-- Configurations

Open `web.config` file and add our module parameters into your Application settings:

```cs
<appSettings>
	...
	<add key="_username" value="Your Email" />
	<add key="_password" value="Your Password" />
	<add key="_secretkey" value="API Secret key" />
	<add key="_publickey" value="API Public key" />
	<add key="_uri" value="https://dash.e-dna.co/secure" />
	<add key="_timeout" value="1000" />
	<add key="_debug_mode" value="false" />
	<add key="_security_mode" value="monitor" />
	<add key="_autoRedirection" value="false" />
	<add key="_breaker_reset_timeout" value="500" />
	<add key="_breaker_invoc_timeout" value="2000" />
	<add key="_breaker_max_failures" value="2" />
	<add key="_proxy_address" value="http://192.168.10.33:3021" />
	...
</appSettings>
```

##### Definition of each parameter
```js
`_username`: **String**, *++Required++* **The Autentication username to be used in the Http Simple Athentication**.
`_password`: **String**, *++Required++* **The Authentication password to be sent with the _username**.
`_secretkey`: **String**, *++Required++* **Your Application secret key**.
`_publickey`: **String**, *++Optional++* **This key is not required for a server side request**.
`_uri`: **String**, Required **The API endpoint**.
`_timeout`: **Int32** Milliseconds, *++Required++* **This parameter indicates the time limit after which an API call has to be timed out. No synchronous API call would block for more than the value specified to this parameter**.
`_debug_mode`: **Boolean**, *++Required++* **Set this parameter as 'true' if you want to enable logging**.
`_autoRedirection`: **Boolean**, *++Required++* **Set this parameter to 'true' if you want our deep malware scanner to be used, this action will redirect the visitor to our own scanner URI**.
`_breaker_max_failures`: **Int32**, *++Required++* **Set this parameter's value if you want the module to re-try sending a request in case of failure, this param is a need for the reset timeout param to work perfectly**.
`_breaker_invoc_timeout`: **Int32**, *++Required++* **The breaker is set there waiting when to start an action, the actual action is the Http request, so this param is set to tell the module to start an Async call after a given timestamp.**.
`_breaker_reset_timeout`: **Int32**, *++Required++* **In case the module failed this value will again try to launch the Http request to our API, this param works only if there is is a value upper than 1**.
`_proxy_address`: **String**, *++Optional++* **If you want to send requests throughout a proxy address, then simply use this param and set it to your desired address, remember if the proxy IP chosen is blacklisted or a reported address we may block requests untill you fix it.**.
```
Then add our module into your system and server settings:
```cs
<system.web>
	...
	<httpModules>
		...
		<add name="Edna" type="Edna.Secure, Edna"/>
		...
	</httpModules>
	...
</system.web>
...
<system.webServer>
	...
	<modules>
		...
		<add name="Edna" type="Edna.Secure, Edna"/>
		...
	</modules>
</system.webServer>
```

NOTE: For further information about the breaker, please refer to https://github.com/alexandrnikitin/CircuitBreaker.Net, also all the time values are in milliseconds so please be careful when setting a value, one last thing to remember is that all our requests are async.

We are strongly reccomending that you start testing in your development environment before moving to production servers, also note please that each domain requires a new application.
For more help please don't hesitate contact our integration developer jeffery@e-dna.co. 