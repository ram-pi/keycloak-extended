# keycloak-extended
## Package
`mvn clean package`

## Install using Keycloak Deployer
Copy your provider under `standalone/deployments/`.

## Add your own extensions
1. Put your code inside the project
2. Add the reference of your extensions under `src/main/resource/META-INF/services`
3. Add extra dependencies in `pom.xml`

## List of extensions
* saml-attribute-to-group-with-regex-mapper
* saml-attribute-to-group-mapper

## References
[Keycloak Implementing SPI](https://www.keycloak.org/docs/latest/server_development/index.html#_implementing_spi)
