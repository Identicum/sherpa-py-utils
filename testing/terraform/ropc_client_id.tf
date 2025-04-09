resource "keycloak_openid_client" "ropc_client_id" {
  realm_id                 = keycloak_realm.realm.id
  name                     = "ropc_client_id"
  client_id                = "ropc_client_id"
  client_secret            = "ropc_client_secret"
  access_type              = "CONFIDENTIAL"
  standard_flow_enabled    = false
  implicit_flow_enabled    = false
  direct_access_grants_enabled = true
  service_accounts_enabled = false
}

resource "keycloak_openid_client_default_scopes" "ropc_defaultscopes" {
  realm_id       = keycloak_realm.realm.id
  client_id      = keycloak_openid_client.ropc_client_id.id
  default_scopes = [ ]
}

resource "keycloak_openid_client_optional_scopes" "ropc_optionalscopes" {
  depends_on      = [ keycloak_openid_client_default_scopes.ropc_defaultscopes ]
  realm_id        = keycloak_realm.realm.id
  client_id       = keycloak_openid_client.ropc_client_id.id
  optional_scopes = [ ]
}

resource "keycloak_user" "ropc_test_user" {
  realm_id   = keycloak_realm.realm.id
  username   = "ropc_test"
  enabled    = true
  email      = "ropctest@example.com"
  first_name = "ROPC Test"
  last_name  = "User"
  
  initial_password {
    value     = "ropctest123"
    temporary = false
  }
}

