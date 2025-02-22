---
title: One Login SSO for Kubernetes
slug: /deployment/security/one-login/kubernetes
---

# One Login SSO for Kubernetes

Check the Helm information [here](https://artifacthub.io/packages/search?repo=open-metadata).

Once the `Client Id` and `Client Secret` are generated, see the snippet below for an example of where to
place the client id value and update the authorizer configurations in the `values.yaml`.

```yaml
global:
  authorizer:
    className: "org.openmetadata.catalog.security.DefaultAuthorizer"
    # JWT Filter
    containerRequestFilter: "org.openmetadata.catalog.security.JwtFilter"
    initialAdmins: 
    - "suresh"
    botPrincipals: 
    - "ingestion-bot"
    principalDomain: "open-metadata.org"
  authentication:
    provider: "custom-oidc"
    publicKeys: 
    - "{IssuerUrl}/certs"
    authority: "{IssuerUrl}"
    clientId: "{client id}"
    callbackUrl: "http://localhost:8585/callback"
  airflow:
    openmetadata:
      authProvider: "custom-oidc"
      customOidc:
        clientId: ""
        # absolute path of secret file on airflow instance
        secretKeyPath: ""
        tokenEndpoint: ""
```
