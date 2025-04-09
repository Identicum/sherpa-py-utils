resource "keycloak_openid_client" "oidc" {
  realm_id                 = keycloak_realm.realm.id
  name                     = "oidc"
  client_id                = "oidc_client_id"
  client_secret            = "oidc_client_secret"
  access_type              = "CONFIDENTIAL"
  standard_flow_enabled    = false
  implicit_flow_enabled    = false
  direct_access_grants_enabled = true
  service_accounts_enabled = false
}

resource "keycloak_openid_client_default_scopes" "oidc_defaultscopes" {
  realm_id       = keycloak_realm.realm.id
  client_id      = keycloak_openid_client.oidc.id
  default_scopes = [ ]
}

resource "keycloak_openid_client_optional_scopes" "oidc_optionalscopes" {
  depends_on      = [ keycloak_openid_client_default_scopes.oidc_defaultscopes ]
  realm_id        = keycloak_realm.realm.id
  client_id       = keycloak_openid_client.jwkporter.id
  optional_scopes = [ ]
}

resource "keycloak_user" "oidc_test_user" {
  realm_id   = keycloak_realm.realm.id
  username   = "oidc_test"
  enabled    = true
  email      = "oidctest@example.com"
  first_name = "OIDC Test"
  last_name  = "User"
  
  initial_password {
    value     = "oidctest123"
    temporary = false
  }
}

