# NIA SAML Extensions Configuration

This provider adds NIA/eIDAS SAML extensions to outgoing SAML authentication requests.

It can be configured through Keycloak SPI provider configuration.

## Provider ID

```text
nia-saml-extensions
```

## Configuration options

| Option | Description | Default           |
|---|---|-------------------|
| `spType` | Value emitted in `<eidas:SPType>` | `public`          |
| `requestedAttributes` | Comma-separated list of requested claims to send | personidentifier* |

## `spType`

Allowed values:

```text
public
private
```

Example:
```properties
spType=public
```

If the value is missing or invalid, the provider falls back to `public`

## `requestedAttributes`

The `requestedAttributes` option configures which predefined claims are sent in the SAML request.

Format:
```text
ClaimName*,ClaimName,ClaimName:value
```
Example:
```properties
requestedAttributes=PersonIdentifier*,CurrentGivenName,IsAgeOver:18,countryCodeOfBirth,phonenumber
```
The claim name is case-insensitive and must match one of the predefined claim names.
If a claim name ends in '*', it is required.

A claim may include a value using `:`:
```text
IsAgeOver:18
```
This produces an `<eidas:AttributeValue>` for that requested attribute.

## Supported claims

| Claim name | SAML attribute URI | Supports value |
|---|---|---:|
| `PersonIdentifier` | `http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier` | no |
| `CurrentGivenName` | `http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName` | no |
| `CurrentFamilyName` | `http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName` | no |
| `CurrentAddress` | `http://eidas.europa.eu/attributes/naturalperson/CurrentAddress` | no |
| `DateOfBirth` | `http://eidas.europa.eu/attributes/naturalperson/DateOfBirth` | no |
| `PlaceOfBirth` | `http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth` | no |
| `countryCodeOfBirth` | `http://www.stork.gov.eu/1.0/countryCodeOfBirth` | no |
| `eMail` | `http://www.stork.gov.eu/1.0/eMail` | no |
| `age` | `http://www.stork.gov.eu/1.0/age` | no |
| `IsAgeOver` | `http://www.stork.gov.eu/1.0/isAgeOver` | yes |
| `phonenumber` | `http://schemas.eidentita.cz/moris/2016/identity/claims/phonenumber` | no |
| `tradresaid` | `http://schemas.eidentita.cz/moris/2016/identity/claims/tradresaid` | no |
| `idtype` | `http://schemas.eidentita.cz/moris/2016/identity/claims/idtype` | no |
| `idnumber` | `http://schemas.eidentita.cz/moris/2016/identity/claims/idnumber` | no |

## Default configuration

If `requestedAttributes` is not configured, the provider uses the default set:
```properties
requestedAttributes=PersonIdentifier,CurrentGivenName,CurrentFamilyName,CurrentAddress,DateOfBirth,PlaceOfBirth,countryCodeOfBirth,eMail,age,IsAgeOver:18,phonenumber,tradresaid,idtype,idnumber
```
The default `spType` is:
```properties
spType=public
```
## Keycloak configuration

Provider settings should be configured as Keycloak SPI options.

The general format is:
```text
spi-saml-authentication-preprocessor-nia-saml-extensions-<property-name>
```
Camel-case Java config names are written as kebab-case in Keycloak configuration:

| Provider option | Keycloak property name |
|---|---|
| `spType` | `sp-type` |
| `requestedAttributes` | `requested-attributes` |

## Configuration in `keycloak.conf`

Add the following to `conf/keycloak.conf`:
```properties
spi-saml-authentication-preprocessor-nia-saml-extensions-sp-type=public
spi-saml-authentication-preprocessor-nia-saml-extensions-requested-attributes=PersonIdentifier,CurrentGivenName,IsAgeOver:18,countryCodeOfBirth,phonenumber
```
Then restart Keycloak.

## Configuration using command-line flags

For production mode:

```bash
bin/kc.sh start \
--spi-saml-authentication-preprocessor-nia-saml-extensions-sp-type=public \
--spi-saml-authentication-preprocessor-nia-saml-extensions-requested-attributes=PersonIdentifier,CurrentGivenName,IsAgeOver:18,countryCodeOfBirth,phonenumber
```

## Configuration using environment variables

Environment variables use uppercase names and underscores:

```bash
KC_SPI_SAML_AUTHENTICATION_PREPROCESSOR_NIA_SAML_EXTENSIONS_SP_TYPE=public
KC_SPI_SAML_AUTHENTICATION_PREPROCESSOR_NIA_SAML_EXTENSIONS_REQUESTED_ATTRIBUTES=PersonIdentifier,CurrentGivenName,IsAgeOver:18,countryCodeOfBirth,phonenumber
```

## Example output

With this configuration:
```properties
spType=public
requestedAttributes=PersonIdentifier,CurrentGivenName,IsAgeOver:18,countryCodeOfBirth,phonenumber
```
The provider emits NIA/eIDAS extensions equivalent to:
```xml
<eidas:SPType>public</eidas:SPType>
<eidas:RequestedAttributes>
    <eidas:RequestedAttribute
      Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      isRequired="false" />
    <eidas:RequestedAttribute
      Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      isRequired="false" />
    <eidas:RequestedAttribute
      Name="http://www.stork.gov.eu/1.0/isAgeOver"
      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      isRequired="false">
      <eidas:AttributeValue>18</eidas:AttributeValue>
    </eidas:RequestedAttribute>
    <eidas:RequestedAttribute
      Name="http://www.stork.gov.eu/1.0/countryCodeOfBirth"
      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      isRequired="false" />
    <eidas:RequestedAttribute
      Name="http://schemas.eidentita.cz/moris/2016/identity/claims/phonenumber"
      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      isRequired="false" />
</eidas:RequestedAttributes>
```
## Notes

- Claim names are case-sensitive.
- Unknown claim names are ignored.
- Attribute order follows the order in `requestedAttributes`.
- Values are only supported for claims that explicitly allow them.
- Requested attributes are emitted with `isRequired="false"` unless the claim name ends in `*`.
```
