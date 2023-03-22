# OpenMetadata-Ranger Authorizer

This submodule implements the OpenMetadata Authorizer interface by using 
Apache Ranger to pull and evaluate policies.

## Configuration

To use this Authorizer, in the `openmetadata.yaml` file, the `authorizerConfiguration.className` field must have 
the value `org.openmetadata.security.ranger.RangerAuthorizer`.

The `authorizerConfiguration.extraConfiguration` objects expects the following keys:
```yaml
authorizerConfiguration:
  className: org.openmetadata.security.ranger.RangerAuthorizerImpl
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
[Example](ranger/openmetadata-authorization-ranger/conf/openmetadata-ranger-security.xml)

`ranger.policy-manager-ssl.configuraion` - optional SSL certificate validation for Ranger policy manager.
[Example](ranger/openmetadata-authorization-ranger/conf/openmetadata-ranger-policymgr-ssl.xml)

`ranger.audit.configuration` - optional configuration for access auditing.
[Example](ranger/openmetadata-authorization-ranger/conf/openmetadata-ranger-audit.xml)

`hadoop.configuration` - Hadoop's `UserGroupInformation` configuration, used for pulling users' groups from LDAP.
[Example](ranger/openmetadata-authorization-ranger/conf/openmetadata-ranger-hadoop.xml)

Example configuration files are provided in 
[`openmetadata-authorization-ranger/conf`](conf).

Note that these are only a subset of the configurations accepted by Ranger plugins. Unfortunately a fully comprehensive 
list does not exist.

## Class Loading and RangerPluginClassLoader

Apache Ranger plugins are built for Java 8 and have too many dependency conflicts to run in the 
same classpath as OpenMetadata.

Because of this, both Ranger modules are not explicitly added as dependencies to `openmetadata-service`. The `openmetadata-dist` 
assembly adds artifacts to the build archive which are then loaded dynamically.

We solve this problem by isolating Ranger's classes and dependencies into their own `ClassLoader`,
separated from the `ApplicationClassLoader`. This is done using the [`RangerPluginClassLoader`](https://github.com/apache/ranger/blob/master/ranger-plugin-classloader/src/main/java/org/apache/ranger/plugin/classloader/RangerPluginClassLoader.java)
class, provided by the `org.apache.ranger:ranger-plugin-classloader` package, and the `openmetadata-authorization-ranger-shim`
module.

The `org.openmetadata.security.ranger.RangerAuthorizer` is just a shim class, meaning it has no implementation. 
The implementation is contained by `org.openmetadata.security.ranger.RangerAuthorizerImpl` and other classes in the 
module `openmetadata-authorization-ranger`. The `RangerAuthorizer` class creates an instance of `RangerPluginClassLoader`
that will load the classes and dependencies of `openmetadata-authorization-ranger` by looking for a folder called 
`ranger-openmetadata-plugin-impl`, which needs to be in the same directory that `RangerAuthorizer` was loaded from. 
The shim class `RangerAuthorizer` will replace the current thread's context class loader with its instance of `RangerPluginClassLoader`
before instantiating or calling the implementation class `RangerPluginImpl` and after that switch it back to the original
class loader.

`RangerPluginClassLoader` is a "child-first" class loader - it will try to resolve a class or resource BEFORE calling 
the parent class loader (in this case, the parent is the root application class loader).

The assembly defined in `openmetadata-dist` organizes Ranger dependencies correctly in the `/libs` folder.

### IntelliJ and Interactive Debugging of RangerAuthorizer

Because Ranger modules are not explicit dependencies of `openmetadata-service`, IntelliJ will not pick up the classes for 
`RangerAuthorizer` and its dependencies. 

Before following the steps bellow, build the project (using `mvn clean install -DskipTests`).

IntelliJ can load the needed classes if they are explicitly added to the class path:
1. Create a IntelliJ Run Configuration with the Application target;
2. Use `openmetadata-service` as the classpath module;
3. Use `org.openmetadata.serviceOpenMetadataAppliation` as the entrypoint;
4. Provide the appropriate arguments (e.g.: `server ./conf/openmetadata.yaml`);
5. Use the root project folder as the Working directory;
6. Add extra Ranger JARs to classpath:
   1. Click Modify option -> Modify classpath;
   2. Include `openmetadata-dist/target/openmetadata-${version}/openmetadata-${version}/libs/openmetadata-authorization-ranger-shim-${version}.jar`
   3. Include `openmetadata-dist/target/openmetadata-${version}/openmetadata-${version}/libs/ranger-plugin-classloader-${ranger.verion}.jar`
7. Apply and Save.

To pick up new changes to `RangerAuthorizer` or related classes, a full rebuild of the project is needed (using the 
command above).