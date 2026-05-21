package eu.bindworks.keycloak.nia.saml;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.stream.XMLStreamWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Keycloak SAML Authentication Preprocessor that adds eIDAS extensions
 * required for authentication via NIA (Národní bod pro identifikaci a autentizaci).
 *
 * <p>This preprocessor intercepts outgoing SAML AuthnRequests directed at
 * {@code *.identita.gov.cz} and injects the required {@code <eidas:SPType>}
 * and {@code <eidas:RequestedAttributes>} extension elements.</p>
 */
public class NiaSamlAuthenticationPreprocessor implements SamlAuthenticationPreprocessor {

    private static final Logger LOG = Logger.getLogger(NiaSamlAuthenticationPreprocessor.class);

    public static final String PROVIDER_ID = "nia-saml-extensions";

    private static final String EIDAS_NS = "http://eidas.europa.eu/saml-extensions";
    private static final String EIDAS_PREFIX = "eidas";
    private static final String ATTR_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

    private static final String CONFIG_SP_TYPE = "spType";
    private static final String CONFIG_REQUESTED_ATTRIBUTES = "requestedAttributes";

    private static final String DEFAULT_SP_TYPE = "public";
    private static final String DEFAULT_REQUESTED_ATTRIBUTES = "personidentifier,currentgivenname,currentfamilyname,"
            + "currentaddress,dateofbirth,placeofbirth,countrycodeofbirth,email,age,isageover:18,"
            + "phonenumber,tradresaid,idtype,idnumber";

    private static final Map<String, SupportedAttribute> SUPPORTED_ATTRIBUTES = Map.ofEntries(
            Map.entry("personidentifier", new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", false)),
            Map.entry("currentgivenname", new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName", false)),
            Map.entry("currentfamilyname", new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", false)),
            Map.entry("currentaddress", new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentAddress", false)),
            Map.entry("dateofbirth", new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth", false)),
            Map.entry("placeofbirth", new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth", false)),
            Map.entry("countrycodeofbirth", new SupportedAttribute("http://www.stork.gov.eu/1.0/countryCodeOfBirth", false)),
            Map.entry("email", new SupportedAttribute("http://www.stork.gov.eu/1.0/eMail", false)),
            Map.entry("age", new SupportedAttribute("http://www.stork.gov.eu/1.0/age", false)),
            Map.entry("isageover", new SupportedAttribute("http://www.stork.gov.eu/1.0/isAgeOver", true)),
            Map.entry("phonenumber", new SupportedAttribute("http://schemas.eidentita.cz/moris/2016/identity/claims/phonenumber", false)),
            Map.entry("tradresaid", new SupportedAttribute("http://schemas.eidentita.cz/moris/2016/identity/claims/tradresaid", false)),
            Map.entry("idtype", new SupportedAttribute("http://schemas.eidentita.cz/moris/2016/identity/claims/idtype", false)),
            Map.entry("idnumber", new SupportedAttribute("http://schemas.eidentita.cz/moris/2016/identity/claims/idnumber", false))
    );
    /** Pattern to match NIA identity provider URLs. */
    private static final Pattern NIA_DESTINATION_PATTERN = Pattern.compile(".*identita\\.gov\\.cz.*");

    private String spType = DEFAULT_SP_TYPE;
    private List<RequestedAttribute> requestedAttributes = parseRequestedAttributes(DEFAULT_REQUESTED_ATTRIBUTES);

    class SPTypeNodeGenerator implements SamlProtocolExtensionsAwareBuilder.NodeGenerator {
        @Override
        public void write(XMLStreamWriter writer) throws ProcessingException {
            StaxUtil.writeStartElement(writer, EIDAS_PREFIX, "SPType", EIDAS_NS);
            StaxUtil.writeNameSpace(writer, EIDAS_PREFIX, EIDAS_NS);
            StaxUtil.writeCharacters(writer, spType);
            StaxUtil.writeEndElement(writer);
        }
    }

    class RequestedAttributesNodeGenerator implements SamlProtocolExtensionsAwareBuilder.NodeGenerator {
        @Override
        public void write(XMLStreamWriter writer) throws ProcessingException {
            StaxUtil.writeStartElement(writer, EIDAS_PREFIX, "RequestedAttributes", EIDAS_NS);
            StaxUtil.writeNameSpace(writer, EIDAS_PREFIX, EIDAS_NS);
            for (RequestedAttribute attribute : requestedAttributes) {
                StaxUtil.writeStartElement(writer, EIDAS_PREFIX, "RequestedAttribute", EIDAS_NS);
                StaxUtil.writeAttribute(writer, "Name", attribute.attr.name);
                StaxUtil.writeAttribute(writer, "NameFormat", ATTR_NAME_FORMAT);
                StaxUtil.writeAttribute(writer, "isRequired", "false");

                if (attribute.value != null) {
                    StaxUtil.writeStartElement(writer, EIDAS_PREFIX, "AttributeValue", EIDAS_NS);
                    StaxUtil.writeCharacters(writer, attribute.value);
                    StaxUtil.writeEndElement(writer);
                }

                StaxUtil.writeEndElement(writer);
            }

            StaxUtil.writeEndElement(writer);
        }
    }

    @Override
    public AuthnRequestType beforeSendingLoginRequest(AuthnRequestType authnRequest, AuthenticationSessionModel clientSession) {
        URI destination = authnRequest.getDestination();
        if (destination == null || !NIA_DESTINATION_PATTERN.matcher(destination.toString()).matches()) {
            LOG.debugv("Skipping NIA extensions — destination does not match: {0}", destination);
            return authnRequest;
        }

        LOG.infov("Adding eIDAS extensions for NIA destination: {0}", destination);

        ExtensionsType extensions = authnRequest.getExtensions();
        if (extensions == null) {
            extensions = new ExtensionsType();
            authnRequest.setExtensions(extensions);
        }

        extensions.addExtension(new SPTypeNodeGenerator());
        extensions.addExtension(new RequestedAttributesNodeGenerator());

        return authnRequest;
    }

    /**
     * Creates a DOM element in the eIDAS namespace.
     */
    private Element createEidasElement(Document doc, String localName) {
        return doc.createElementNS(EIDAS_NS, EIDAS_PREFIX + ":" + localName);
    }

    // --- ProviderFactory methods ---

    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        spType = resolveSpType(config);

        String configuredRequestedAttributes = config.get(CONFIG_REQUESTED_ATTRIBUTES);
        requestedAttributes = parseRequestedAttributes(Objects.requireNonNullElse(configuredRequestedAttributes, DEFAULT_REQUESTED_ATTRIBUTES));

        LOG.debugv("Configured NIA SPType: {0}", spType);
        LOG.debugv("Configured NIA requested attributes count: {0}", requestedAttributes.size());
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    private String resolveSpType(Config.Scope config) {
        String configuredSpType = config.get(CONFIG_SP_TYPE, DEFAULT_SP_TYPE);
        if (configuredSpType == null || configuredSpType.isBlank()) {
            return DEFAULT_SP_TYPE;
        }

        String normalizedSpType = configuredSpType.trim().toLowerCase();
        if ("public".equals(normalizedSpType) || "private".equals(normalizedSpType)) {
            return normalizedSpType;
        }

        LOG.warnv("Invalid NIA SPType configured: {0}. Falling back to {1}", configuredSpType, DEFAULT_SP_TYPE);
        return DEFAULT_SP_TYPE;
    }

    private static List<RequestedAttribute> parseRequestedAttributes(String configuredAttributes) {
        List<RequestedAttribute> parsedAttributes = new ArrayList<>();

        if (configuredAttributes == null) {
            return parsedAttributes;
        }

        for (String rawToken : configuredAttributes.split(",")) {
            String token = rawToken.trim();
            if (token.isEmpty()) {
                continue;
            }

            String claimName = token;
            String attributeValue = null;

            int valueSeparatorIndex = token.indexOf(':');
            if (valueSeparatorIndex >= 0) {
                claimName = token.substring(0, valueSeparatorIndex).trim().toLowerCase();
                attributeValue = token.substring(valueSeparatorIndex + 1).trim();
            } else {
                claimName = claimName.trim().toLowerCase();
            }

            SupportedAttribute supportedAttribute = SUPPORTED_ATTRIBUTES.get(claimName);
            if (supportedAttribute == null) {
                LOG.warnv("Ignoring unknown NIA requested attribute: {0}", claimName);
                continue;
            }

            if (!supportedAttribute.supportsValue() && attributeValue != null) {
                LOG.warnv("Ignoring configured value for NIA requested attribute that does not support values: {0}", claimName);
                attributeValue = null;
            }

            if (attributeValue != null && attributeValue.isEmpty()) {
                attributeValue = null;
            }

            parsedAttributes.add(new RequestedAttribute(supportedAttribute, attributeValue));
        }

        return parsedAttributes;
    }

    private record SupportedAttribute(String name, boolean supportsValue) {
    }

    private record RequestedAttribute(SupportedAttribute attr, String value) {
    }
}
