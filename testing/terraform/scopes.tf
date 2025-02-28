resource "keycloak_openid_client_scope" "jwksporter_crud" {
  realm_id               = keycloak_realm.realm.id
  name                   = "jwksporter:crud"
  description            = "Allows CRUD operations"
  include_in_token_scope = true
}

resource "keycloak_openid_client_scope" "jwksporter_sign" {
  realm_id               = keycloak_realm.realm.id
  name                   = "jwksporter:sign"
  description            = "Allows signing operations"
  include_in_token_scope = true
}
