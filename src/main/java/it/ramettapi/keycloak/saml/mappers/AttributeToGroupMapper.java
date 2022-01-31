package it.ramettapi.keycloak.saml.mappers;

import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;

public class AttributeToGroupMapper extends AbstractIdentityProviderMapper implements IdentityProviderMapper {

	// logger ------------------------------------------------
	private static final Logger logger = Logger.getLogger(AttributeToGroupMapper.class);

	public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

	public static final String GROUP_ATTRIBUTE = "group-attribute";
	public static final String GROUP_ATTRIBUTE_FRIENDLY = "group-attribute";
	public static final String GROUP_ATTRIBUTE_VALUE = "group-attribute-value";
	public static final String GROUP = "group";

	public static final String PROVIDER_ID = "saml-attribute-to-group-mapper";

	static {
		ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        
        property.setName(GROUP_ATTRIBUTE);
        property.setLabel("Attribute Name");
        property.setHelpText("Name of attribute to search for in assertion.  You can leave this blank and specify a friendly name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(GROUP_ATTRIBUTE_FRIENDLY);
        property.setLabel("Friendly Name");
        property.setHelpText("Friendly name of attribute to search for in assertion.  You can leave this blank and specify a name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(GROUP_ATTRIBUTE_VALUE);
        property.setLabel("Attribute Value");
        property.setHelpText("Value the attribute must have.  If the attribute is a list, then the value must be contained in the list.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(GROUP);
        property.setLabel("Group");
        property.setHelpText("Group to grant to user. i.e. /Group1/SubGroup2");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
	}

	@Override
	public String[] getCompatibleProviders() {
		return COMPATIBLE_PROVIDERS;
	}

	@Override
	public String getDisplayCategory() {
		return null;
	}

	@Override
	public String getDisplayType() {
		return "SAML Attribute to Group Mapper";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		return "Use SAML attributes to link users and groups";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}
	
	@Override
	public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
			IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
		String groupName = mapperModel.getConfig().get(GROUP);
        if (isAttributePresent(mapperModel, context)) {
            GroupModel group = KeycloakModelUtils.findGroupByPath(realm, groupName);
            if (group == null) {
            	logger.info(("[AttributeToGroupMapper] Unable to find group: " + groupName));
            	return;
            }
            user.joinGroup(group);
        }
	}

	@Override
	public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
			IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

		String groupName = mapperModel.getConfig().get(GROUP);
        GroupModel group = KeycloakModelUtils.findGroupByPath(realm, groupName);
        if (group == null) {
        	logger.info(("[AttributeToGroupMapper] Unable to find group: " + groupName));
        }
        boolean attributeFound = false;
        if (isAttributePresent(mapperModel, context)) {
        	logger.info("[AttributeToGroupMapper] updateBrokered user will join group " + mapperModel.getConfig().get(GROUP_ATTRIBUTE));
            user.joinGroup(group);
            attributeFound = true;
        }
        
        /*
        if (!attributeFound) {
        	logger.info("[AttributeToGroupMapper] updateBrokered no attribute value found for group " + mapperModel.getConfig().get(GROUP_ATTRIBUTE));
        }
        */
		
	}
	
	protected boolean isAttributePresent(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String name = mapperModel.getConfig().get(GROUP_ATTRIBUTE);
        if (name != null && name.trim().equals("")) name = null;
        String friendly = mapperModel.getConfig().get(GROUP_ATTRIBUTE_FRIENDLY);
        if (friendly != null && friendly.trim().equals("")) friendly = null;
        String desiredValue = mapperModel.getConfig().get(GROUP_ATTRIBUTE_VALUE);
        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        for (AttributeStatementType statement : assertion.getAttributeStatements()) {
            for (AttributeStatementType.ASTChoiceType choice : statement.getAttributes()) {
                AttributeType attr = choice.getAttribute();
                if (name != null && !name.equals(attr.getName())) continue;
                for (Object val : attr.getAttributeValue()) {
                    if (val.equals(desiredValue)) return true;
                }
            }
        }
        return false;
    }
}