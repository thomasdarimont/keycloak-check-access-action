package com.github.thomasdarimont.keycloak.checkaccess;

import com.google.auto.service.AutoService;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.messages.Messages;

import java.util.List;

public class CheckAccessAction implements RequiredActionProvider {

    private static final Logger LOG = Logger.getLogger(CheckAccessAction.class);

    public static final String ID = "auth-check-access-action";

    public static final String CLIENT_ACCESS_ROLE_CONFIG_KEY = "clientAccessRole";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

        var authSession = context.getAuthenticationSession();
        var user = context.getUser();
        var client = context.getAuthenticationSession().getClient();

        // check to avoid repeated access checks within an auth sessions
        if (authSession.getAuthNote(ID) != null) {
            return;
        }
        // mark check access executed
        authSession.setAuthNote(ID, "true");

        var config = context.getConfig();
        if (config == null) {
            LOG.debugf("ignore access check without configuration. realm=%s client=%s userId=%s", //
                    context.getRealm(), client.getClientId(), user.getId());
            context.success();
            return;
        }

        String clientAccessRoleName = config.getConfigValue(CLIENT_ACCESS_ROLE_CONFIG_KEY);
        RoleModel clientRole = client.getRole(clientAccessRoleName);
        if (clientRole == null) {
            LOG.debugf("ignore access check for client without role configuration. realm=%s client=%s userId=%s", //
                    context.getRealm(), client.getClientId(), user.getId());
            return;
        }

        authSession.addRequiredAction(ID);
    }

    protected void showErrorPage(RequiredActionContext context, UserModel user) {
        var session = context.getSession();
        var loginForm = session.getProvider(LoginFormsProvider.class);
        loginForm.setError(Messages.ACCESS_DENIED, user.getUsername());
        context.challenge(loginForm.createErrorPage(Response.Status.FORBIDDEN));
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {

        var user = context.getUser();
        var client = context.getAuthenticationSession().getClient();

        var config = context.getConfig();
        String clientAccessRoleName = config.getConfigValue(CLIENT_ACCESS_ROLE_CONFIG_KEY);
        RoleModel clientRole = client.getRole(clientAccessRoleName);

        if (!user.hasRole(clientRole)) {
            context.failure(Messages.ACCESS_DENIED);
            LOG.debugf("Access denied due to missing client access role. realm=%s client=%s userId=%s missingRole=%s", //
                    context.getRealm(), client.getClientId(), user.getId(), clientAccessRoleName);
            showErrorPage(context, user);
            context.getEvent() //
                    .detail("access_check", "failed") //
                    .detail("access_check_failed", "missing_client_role:" + clientAccessRoleName) //
                    .error(Messages.ACCESS_DENIED);
            return;
        }

        context.getEvent().detail("access_check", "ok");
        LOG.debugf("Access granted by client access role. realm=%s client=%s userId=%s missingRole=%s", //
                context.getRealm(), client.getClientId(), user.getId(), clientAccessRoleName);
        context.success();
    }

    @Override
    public void processAction(RequiredActionContext context) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @AutoService(RequiredActionFactory.class)
    public static class Factory implements RequiredActionFactory {

        private static final CheckAccessAction INSTANCE = new CheckAccessAction();

        @Override
        public String getId() {
            return ID;
        }

        @Override
        public String getDisplayText() {
            return "Custom: Check Access";
        }

        @Override
        public RequiredActionProvider create(KeycloakSession session) {
            return INSTANCE;
        }

        @Override
        public void init(Config.Scope config) {
            // NOOP
        }

        @Override
        public void postInit(KeycloakSessionFactory factory) {
            // NOOP
        }

        @Override
        public List<ProviderConfigProperty> getConfigMetadata() {
            //
            var builder = ProviderConfigurationBuilder.create() //
                    .property() //
                    .name(CLIENT_ACCESS_ROLE_CONFIG_KEY) //
                    .label("Client role that grants access") //
                    .helpText("""
                            Defines the client role required to grant access to a client. \
                            If a client does not define this role, the access check is skipped.""") //
                    .type(ProviderConfigProperty.STRING_TYPE) //
                    .defaultValue(String.join("access")) //
                    .add();
            return builder.build();
        }

        @Override
        public void close() {
            // NOOP
        }
    }
}
