resource "keycloak_openid_client" "jwkporter" {
  realm_id                 = keycloak_realm.realm.id
  name                     = "jwkporter"
  client_id                = "jwkporter_client_id"
  client_secret            = "jwkporter_client_secret"
  access_type              = "CONFIDENTIAL"
  standard_flow_enabled    = false
  implicit_flow_enabled    = false
  direct_access_grants_enabled = false
  service_accounts_enabled = true
}

resource "keycloak_openid_client_default_scopes" "jwkporter_defaultscopes" {
  realm_id       = keycloak_realm.realm.id
  client_id      = keycloak_openid_client.jwkporter.id
  default_scopes = [ keycloak_openid_client_scope.jwksporter_crud.name, keycloak_openid_client_scope.jwksporter_sign.name ]
}

resource "keycloak_openid_client_optional_scopes" "jwkporter_optionalscopes" {
  depends_on      = [ keycloak_openid_client_default_scopes.jwkporter_defaultscopes ]
  realm_id        = keycloak_realm.realm.id
  client_id       = keycloak_openid_client.jwkporter.id
  optional_scopes = [ ]
}
