# OpenMetadata-Ranger Authorizer

This submodule implements the OpenMetadata Authorizer interface by using 
Apache Ranger to pull and evaluate policies.

## Configuration

To use this Authorizer, in the `openmetadata.yaml` file, the `authorizerConfiguration.className` field must have 
the value `org.openmetadata.security.ranger.RangerAuthorizer`.

The `authorizerConfiguration.extraConfiguration` objects expects the following keys:
```yaml
authorizerConfiguration:
  className: org.openmetadata.security.ranger.RangerAuthorizer
  extraConfiguration:
    "ranger.service.name": "openmetadata-localhost"
    "hadoop.configuration": "./conf/ranger/openmetadata-ranger-hadoop.xml"
    "ranger.audit.configuration" : "./conf/ranger/openmetadata-ranger-audit.xml"
    "ranger.security.configuration" : "./conf/ranger/openmetadata-ranger-security.xml"
    "ranger.policy-manager-ssl.configuration" : "./conf/ranger/openmetadata-ranger-policymgr-ssl.xml"
```

`ranger.service.name` - service name that needs to match up with an OpenMetadata service instance created in 
Ranger.

`ranger.security.configuration` - connection to Ranger policy manager. 
[Example](conf/openmetadata-ranger-security.xml)

`ranger.policy-manager-ssl.configuraion` - optional SSL certificate validation for Ranger policy manager.
[Example](conf/openmetadata-ranger-policymgr-ssl.xml)

`ranger.audit.configuration` - optional configuration for access auditing.
[Example](conf/openmetadata-ranger-audit.xml)

`hadoop.configuration` - Hadoop's `UserGroupInformation` configuration, used for pulling users' groups from LDAP.
[Example](conf/openmetadata-ranger-hadoop.xml)

Example configuration files are provided in 
[`openmetadata-authorization-ranger/conf`](conf).

Note that these are only a subset of the configurations accepted by Ranger plugins. Unfortunately a fully comprehensive 
list does not exist.