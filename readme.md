Check Access Action
---

Simple required action to check if a given user has a client role required to access to the client.

# Build
```
mvn clean package
```

# Deploy
Add `target/keycloak-check-access-action.jar` to `$KEYCLOAK_HOME/providers` folder.
