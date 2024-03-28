// #*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
// A test program demonstrating that the Azure KeyVault client doesn't
// respect proxy settings when acquiring authentication tokens.
//
// TODO: Link to the GitHub issue.

using Azure.Core;
using Azure.Core.Diagnostics;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

using System.CommandLine;
using System.CommandLine.Help;
using System.CommandLine.Parsing;
using System.Net;

namespace Medynski;

public sealed class KeyVaultProxy : IDisposable
{
  // ==========================================================================
  // Construction

  // --------------------------------------------------------------------------
  // Construct with the command line arguments.
  //
  // Throws ArgumentException on any errors.
  //
  public KeyVaultProxy(string[] args)
  {
    // Read the command line arguments into our private members.
    RootCommand options = new("Azure KeyVault Proxy Test");

    Option<bool> helpOption = new(
      "--help",
      () => false,
      "Emit this help.");
    options.Add(helpOption);

    Option<LogLevel> logLevelOption = new(
      "--log-level",
      () => LogLevel.Information,
      "Set the log level as a number.");
    logLevelOption.AddAlias("-l");
    options.Add(logLevelOption);

    Option<string> kvUrlOption = new(
      "--url",
      "The URL of the target Azure Key Vault.");
    kvUrlOption.AddAlias("-u");
    options.Add(kvUrlOption);

    Option<string> tenantIdOption = new(
      "--tenant-id",
      "The Azure Key Vault tenant ID.");
    tenantIdOption.AddAlias("-t");
    options.Add(tenantIdOption);

    Option<string> appIdOption = new(
      "--app-id",
      "The Azure Key Vault application ID.");
    appIdOption.AddAlias("-a");
    options.Add(appIdOption);

    Option<string> secretOption = new(
      "--secret",
      "The secret to use for Azure Key Vault authentication.  Specify either "
      + "this or --cert-path, but not both.");
    secretOption.AddAlias("-s");
    options.Add(secretOption);

    Option<string> certPathOption = new(
      "--cert-path",
      "The path to the certificate file to use for Azure Key Vault "
      + "authentication.  Specify either this or --secret, but not both.");
    certPathOption.AddAlias("-c");
    options.Add(certPathOption);

    Option<string> keyOption = new(
      "--key",
      "The key of the secret to obtain.");
    keyOption.AddAlias("-k");
    options.Add(keyOption);

    Option<string?> proxyOption = new(
      "--proxy",
      () => null,
      "The proxy host:port; omit for direct connection.");
    proxyOption.AddAlias("-p");
    options.Add(proxyOption);

    Option<bool> globalProxyOption = new(
      "--global-proxy",
      () => false,
      "If --proxy is specified, use it as the global HttpClient.DefaultProxy "
      + "instead of the per-instance HttpClient proxy.");
    options.Add(globalProxyOption);

    var parseResult = options.Parse(args);

    if (parseResult.GetValueForOption(helpOption))
    {
        new HelpBuilder(LocalizationResources.Instance)
            .Write(options, Console.Out);
        throw new ArgumentException("Help requested");
    }

    _logLevel = parseResult.GetValueForOption(logLevelOption);

    try
    {
      var kvUrlString = GetRequiredString(parseResult, kvUrlOption);
      _kvUrl = new Uri(kvUrlString);
    }
    catch (UriFormatException ex)
    {
      throw new ArgumentException(
        $"Error: --url must be a valid URL: {ex.Message}");
    }

    _tenantId = GetRequiredString(parseResult, tenantIdOption);
    _appId = GetRequiredString(parseResult, appIdOption);

    _secret = parseResult.GetValueForOption(secretOption);
    _certPath = parseResult.GetValueForOption(certPathOption);
    
    if ((_secret is null && _certPath is null)
        || (_secret is not null && _certPath is not null))
    {
      throw new ArgumentException(
        "Error: Specify either --secret or --cert-path, but not both.");
    }

    _key = GetRequiredString(parseResult, keyOption);
    
    var proxyHostPort = parseResult.GetValueForOption(proxyOption);
    if (proxyHostPort is not null)
    {
      var proxyParts = proxyHostPort.Split(':');
      if (proxyParts.Length != 2)
      {
        throw new ArgumentException(
          "Error: --proxy must be in the form host:port.");
      }
  
      _proxyHost = proxyParts[0];
      
      try
      {
        _proxyPort = UInt16.Parse(proxyParts[1]);
      }
      catch (Exception ex)
      when (ex is FormatException || ex is OverflowException)
      {
        throw new ArgumentException(
          $"Error: --proxy port must be a valid uint16: {ex.Message}");
      }
    }

    _globalProxy = parseResult.GetValueForOption(globalProxyOption);
  }
  
  // --------------------------------------------------------------------------
  // Dispose of our private members.
  //
  public void Dispose()
  {
    _httpClient?.Dispose();
    _proxyRestorer?.Dispose();
  }

  // ==========================================================================
  // Interface

  // --------------------------------------------------------------------------
  public int Run()
  { 
    // Log to the console.
    using ILoggerFactory logFactory =
      LoggerFactory.Create(
        (ILoggingBuilder builder) =>
        {
          builder
          .SetMinimumLevel(_logLevel)
          // This doesn't appear to log HttpClient messages unfortunately.
          .AddFilter("System.Net.Http", LogLevel.Debug)
          .AddSimpleConsole(
            (SimpleConsoleFormatterOptions options) =>
            {
              options.IncludeScopes = true;
              options.SingleLine = true;
              options.TimestampFormat = "HH:mm:ss.fff ";
              options.ColorBehavior = LoggerColorBehavior.Enabled;
            });
        });
    
    var log = logFactory.CreateLogger(nameof(KeyVaultProxy));
    // Send Azure debugging to the log.
    using AzureEventSourceListener _azureLogger = new(
      (args, message) =>
      {
        using var scope = log.BeginScope("Azure");
        
        // Core events are logged at Debug.
        if (args.EventSource.Name == "Azure-Core")
        {
          log.LogDebug(message);
        }
        // Everything else is logged at Trace.
        else
        {
          log.LogTrace(message);
        }
      },
      // Ask for all events of all levels.
      level: System.Diagnostics.Tracing.EventLevel.LogAlways);
    
    // We may need to specify a custom HTTP handler so we will need some
    // SecretClient options.
    SecretClientOptions secretOptions = new();

    // Are we using a proxy?
    if (_proxyHost is not null)
    {
      // Yes, so set it up with the given host/port.
      var proxy = new WebProxy(_proxyHost, _proxyPort)
      {
          BypassProxyOnLocal = false,
          UseDefaultCredentials = false
      };

      // Is it global?
      if (_globalProxy)
      {
        // Ensure we restore the default proxy regardless of how we exit.
        _proxyRestorer = new();

        // Assign our proxy to HttpClient's default proxy so all HttpClient
        // instances without their own explicit proxy will use this one.
        //
        // This seems to be the only way to have SecretClient use the proxy
        // for token acquisition requests.
        //
        HttpClient.DefaultProxy = proxy;
      }
      // No, so we need to use a custom HttpClient.
      else
      {
        // Create HttpClient that uses our proxy.
        _httpClient = new(
          new HttpClientHandler
          {
            Proxy = proxy,
            UseProxy = true
          });
        
        // Tell SecretClient to use our HttpClient, and thus our proxy.
        //
        // Unfortunately, SecretClient seems to only use this HttpClient for
        // KeyVault requests.  It uses a different HttpClient for token
        // acquisition, thus ignoring our proxy for those requests.
        //
        secretOptions.Transport = new HttpClientTransport(_httpClient);
      }
    }

    TokenCredential credential =
        _secret is not null
        ? new ClientSecretCredential(
            _tenantId, _appId, _secret,
            // Supply the same transport as the SecretClient, which will
            // configure a proxy if necessary.
            //
            // This fixes the issue described here:
            //
            // https://github.com/Azure/azure-sdk-for-net/issues/43038
            // 
            new(){ Transport = secretOptions.Transport })
        : new ClientCertificateCredential(
            _tenantId, _appId, _certPath,
            // Same transport as the SecretClient.
            new(){ Transport = secretOptions.Transport });
    
    log.LogInformation(
      $"Creating SecretClient for vault URL={_kvUrl} tenantId={_tenantId} "
      + $"appId={_appId}...");

    log.LogInformation(
      $"Using auth type="
      + (_secret is not null ? "secret" : $"cert ({_certPath})"));
    
    if (_proxyHost is not null)
    {
      log.LogInformation(
        $"Using proxy {_proxyHost}:{_proxyPort} "
        + (_globalProxy ? " (global)" : ""));
    }
      
    SecretClient secrets = new(_kvUrl, credential, secretOptions);

    log.LogInformation($"Getting secret for key={_key}...");
    
    try
    {
      var kvSecret = secrets.GetSecret(_key);
      var kvValue = kvSecret.Value;
      log.LogInformation(
        $"Secret for key={_key} is: id={kvValue.Id} name={kvValue.Name} "
        + $"value={kvValue.Value}");
    }
    catch (Exception ex)
    {
      log.LogError($"Failed to fetch secret for key={_key}: {ex.Message}");
      return 1;
    }

    return 0;
  }

  // ==========================================================================
  // Helpers

  // --------------------------------------------------------------------------
  // An RAII helper to restore the HttpClient's default proxy.
  //
  class ProxyRestorer : IDisposable
  {
    public ProxyRestorer()
    {
      _oldProxy = HttpClient.DefaultProxy;
    }

    public void Dispose()
    {
      HttpClient.DefaultProxy = _oldProxy;
    }

    private readonly IWebProxy _oldProxy;
  }

  // --------------------------------------------------------------------------
  // Get the value of a required option.
  //
  // Throws ArgumentException if the option is not present.
  //
  private T GetRequired<T>(
    ParseResult result,
    Option<T> option)
  where T : notnull
  {
    var optionValue = result.GetValueForOption(option);

    if (optionValue is null)
    {
      throw new ArgumentException($"Error: {option.Name} is required.");
    }

    return optionValue;
  }

  // --------------------------------------------------------------------------
  // Get the value of a required string option.
  //
  // Throws ArgumentException if the option is not present or its value is the
  // empty string.
  //
  private string GetRequiredString(
    ParseResult result,
    Option<string> option)
  {
    var value = GetRequired(result, option);
    if (value.Length == 0)
    {
      throw new ArgumentException($"Error: {option.Name} must not be empty.");
    }
    return value;
  }

  // --------------------------------------------------------------------------
  // The main entry point, called by the .NET runtime.
  //
  public static int Main(string[] args)
  {
    try
    {
      using KeyVaultProxy app = new(args);
      return app.Run();
    }
    catch (ArgumentException ex)
    {
      Console.Error.WriteLine($"Error: {ex.Message}");
      return 1;
    }
  }

  // ==========================================================================
  // Private Members

  // Command line options.
  private readonly LogLevel _logLevel;
  private readonly Uri _kvUrl;
  private readonly string _tenantId;
  private readonly string _appId;
  private readonly string? _secret;
  private readonly string? _certPath;
  private readonly string _key;
  private readonly string? _proxyHost;
  private readonly ushort _proxyPort;
  private readonly bool _globalProxy;

  // Proxy management.
  private ProxyRestorer? _proxyRestorer;
  private HttpClient? _httpClient;
}

// #*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
