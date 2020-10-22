using Hubster.Abstractions.Converters;
using Hubster.Abstractions.Models.Engine;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace WebhookSample.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WebhooksController : ControllerBase
    {
        private readonly ILogger<WebhooksController> _logger;

        public WebhooksController(ILogger<WebhooksController> logger)
        {
            _logger = logger;
        }

        [HttpPost("activities")]
        public async Task<IActionResult> ReceiveActivities()
        {
            var publicKey = Request.Headers["x-hubster-public-key"].ToString();
            var headerSignature = Request.Headers["x-hubster-signature"].ToString();

            if (string.IsNullOrWhiteSpace(publicKey) 
            || string.IsNullOrWhiteSpace(headerSignature))
            {
                return StatusCode((int)HttpStatusCode.Forbidden, "Forbidden");
            }

            var privateKey = await GetPrivateKeyAsync(publicKey);

            var rawBody = new byte[(int)Request.ContentLength];
            await Request.BodyReader.AsStream().ReadAsync(rawBody);

            // now preform HMAC signature check

            using (var hasher = new HMACSHA256(privateKey))
            {
                var byteSignature = hasher.ComputeHash(rawBody);
                var signature = Convert.ToBase64String(byteSignature);

                if (signature != headerSignature)
                {
                    _logger.LogWarning("Invalid signature");
                    return StatusCode((int)HttpStatusCode.Forbidden, "Forbidden");
                }
            }

            // at this point the request is now trusted 
            // and it came from Hubster

            var json = Encoding.UTF8.GetString(rawBody);
            var activities = JsonConvert.DeserializeObject<SystemOutboundDataModel>(json, new DirectMessageJsonConverter());

            // you now have a list of activities you can process, etc.
            
            return Ok(); 
        }

        private Task<byte[]> GetPrivateKeyAsync(string publicKey)
        {
            // NOTE: for sake of sample, we are hard-coding the private key
            // however, you should use the public key as an indexer to get
            // the private key in some secure store like KeyVault, etc. 

            var privateKey = "FA96D15568654A4482772E00BA941BCB";
            var bPrivateKey = Encoding.UTF8.GetBytes(privateKey);

            return Task.FromResult(bPrivateKey);
        }
    }
}
