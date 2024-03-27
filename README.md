# azure-key-vault-proxy
Minimal project to reproduce the issue that Azure SecretClient doesn't obey
proxy settings for login token acquisition.

https://github.com/Azure/azure-sdk-for-net/issues/43038

We can configure the SecretClientOptions.Transport with a suitable proxy, and
requests to the Azure KeyVault obey this proxy.  However, requests from within
SecretClient to obtain login tokens _do not_ obey the proxy, and thus they fail
to complete.  If a proxy is set via SecretClientOptions.Transport, it should be
used for all requests made by SecretClient or any libs/functions that it uses.

Use this minimal dotnet console app to reproduce the issue.  Run with --help for
options related to Azure Key Vault and whether or not a proxy is used.

### All egress allowed, no proxy specified:
```
$ dotnet run -- -u https://<keyvault>/ -t <tenantId> -a <appId> -c <cert.pem> -k my-secret-name

11:54:30.338 info: KeyVaultProxy[0] Creating SecretClient for vault URL=https://<keyvault>/ tenantId=<tenantId> appId=<appId>...
11:54:30.351 info: KeyVaultProxy[0] Using auth type=cert (cert.pem)
11:54:30.353 info: KeyVaultProxy[0] Getting secret for key=my-secret-name...
11:54:31.606 info: KeyVaultProxy[0] Secret for key=my-secret-name is: id=https://<keyvault>/secrets/my-secret-name/945c0e7946314f90bb3d5e6f74e1d120 name=my-secret-name value=shhh_secret
```

### No egress allowed, no proxy specified:

Configure an HTTPS proxy on localhost:8888, for example
[tinyproxy](https://tinyproxy.github.io/).

Configure iptables to reject all outbound traffic except from the proxy:
```
# iptables -F OUTPUT
# iptables -A OUTPUT -j ACCEPT -m owner --uid-owner tinyproxy
# iptables -A OUTPUT -j ACCEPT -o lo
# iptables -A OUTPUT -j REJECT
```

```
$ dotnet run -- -u https://<keyvault>/ -t <tenantId> -a <appId> -c <cert.pem> -k my-secret-name

14:34:13.245 info: KeyVaultProxy[0] Creating SecretClient for vault URL=https://<keyvault>/ tenantId=<tenantId> appId=<appId>...
14:34:13.258 info: KeyVaultProxy[0] Using auth type=cert (cert.pem)
14:34:13.260 info: KeyVaultProxy[0] Getting secret for key=my-secret-name...
14:34:19.074 fail: KeyVaultProxy[0] Failed to fetch secret for key=my-secret-name: Retry failed after 4 tries. Retry settings can be adjusted in ClientOptions.Retry or by configuring a custom retry policy in ClientOptions.RetryPolicy. (Connection refused (<keyvault>:443)) (Connection refused (<keyvault>:443)) (Connection refused (<keyvault>:443)) (Connection refused (<keyvault>:443))
```

Note that the initial connection to the Key Vault is refused, as expected.

### No egress allowed, SecretClient proxy specified:
```
$ dotnet run -- -u https://<keyvault>/ -t <tenantId> -a <appId> -c <cert.pem> -k my-secret-name -p localhost:8888

14:36:14.837 info: KeyVaultProxy[0] Creating SecretClient for vault URL=https://<keyvault>/ tenantId=<tenantId> appId=<appId>...
14:36:14.848 info: KeyVaultProxy[0] Using auth type=cert (cert.pem)
14:36:14.848 info: KeyVaultProxy[0] Using proxy localhost:8888
14:36:14.850 info: KeyVaultProxy[0] Getting secret for key=my-secret-name...
14:36:21.633 fail: KeyVaultProxy[0] Failed to fetch secret for key=my-secret-name: ClientCertificateCredential authentication failed: Retry failed after 4 tries. Retry settings can be adjusted in ClientOptions.Retry or by configuring a custom retry policy in ClientOptions.RetryPolicy. (Network is unreachable (login.microsoftonline.com:443)) (Network is unreachable (login.microsoftonline.com:443)) (Network is unreachable (login.microsoftonline.com:443)) (Network is unreachable (login.microsoftonline.com:443)) See the troubleshooting guide for more information. https://aka.ms/azsdk/net/identity/clientcertificatecredential/troubleshoot
```

Now we see that the login token requests are failing, because they aren't using
the proxy!  This can be corroborated by inspecting the tinyproxy logs and noting
that only the initial Key Vault was tunneled through the proxy.  The login token
requests did not pass throug the proxy.

### No egress allowed, HttpClient.DefaultProxy specified:
```
$ dotnet run -- -u https://<keyvault>/ -t <tenantId> -a <appId> -c <cert.pem> -k my-secret-name -p localhost:8888 --global-proxy

14:37:50.710 info: KeyVaultProxy[0] Creating SecretClient for vault URL=https://<keyvault>/ tenantId=<tenantId> appId=<appId>...
14:37:50.720 info: KeyVaultProxy[0] Using auth type=cert (cert.pem)
14:37:50.721 info: KeyVaultProxy[0] Using proxy localhost:8888  (global)
14:37:50.722 info: KeyVaultProxy[0] Getting secret for key=my-secret-name...
14:37:52.433 info: KeyVaultProxy[0] Secret for key=my-secret-name is: id=https://<keyvault>/secrets/my-secret-name/945c0e7946314f90bb3d5e6f74e1d120 name=my-secret-name value=shhh_secret
```

Everything works when the global HttpClient.DefaultProxy is specified.  This
isn't a suitable solution though, since other HTTP connections within the app
may rely on a default proxy specified by environment variables for example.
