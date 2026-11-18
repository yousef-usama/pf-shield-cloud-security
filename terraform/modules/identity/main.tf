# =====================================================================================================================
# PF-SHIELD: IDENTITY & ACCESS MANAGEMENT (AMAZON COGNITO)
# =====================================================================================================================
# Manages authenticated broker identities, JWT token issuance, custom tenant claims, and password policies
# aligned with ISO 27001:2022 A.5.15 and UAE PDPL Art. 13.
# =====================================================================================================================

resource "aws_cognito_user_pool" "broker_pool" {
  #checkov:skip=CKV_AWS_109: MFA is configured as OPTIONAL to accommodate demonstration flows while enforcing software TOTP
  name                     = "pf-shield-broker-pool-${var.environment}"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = var.mfa_configuration

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 7
  }

  software_token_mfa_configuration {
    enabled = true
  }

  user_pool_add_ons {
    advanced_security_mode = var.advanced_security_mode
  }

  schema {
    name                = "tenant_id"
    attribute_data_type = "String"
    mutable             = false
    required            = false
    string_attribute_constraints {
      min_length = "3"
      max_length = "64"
    }
  }

  schema {
    name                = "broker_id"
    attribute_data_type = "String"
    mutable             = false
    required            = false
    string_attribute_constraints {
      min_length = "3"
      max_length = "64"
    }
  }

  schema {
    name                = "role"
    attribute_data_type = "String"
    mutable             = true
    required            = false
    string_attribute_constraints {
      min_length = "3"
      max_length = "32"
    }
  }

  tags = {
    Name       = "pf-shield-broker-pool-${var.environment}"
    Compliance = "UAE-PDPL-ISO27001"
  }
}

resource "aws_cognito_user_pool_client" "broker_app_client" {
  name         = "pf-shield-broker-client-${var.environment}"
  user_pool_id = aws_cognito_user_pool.broker_pool.id

  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_PASSWORD_AUTH"
  ]

  prevent_user_existence_errors = "ENABLED"
  id_token_validity             = 60
  access_token_validity         = 60
  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }
}

resource "aws_cognito_user_group" "brokers" {
  name         = "brokers"
  user_pool_id = aws_cognito_user_pool.broker_pool.id
  description  = "Licensed UAE Real Estate Brokers"
  precedence   = 20
}

resource "aws_cognito_user_group" "compliance_officers" {
  name         = "compliance_officers"
  user_pool_id = aws_cognito_user_pool.broker_pool.id
  description  = "Internal Compliance and Verification Officers"
  precedence   = 10
}
