## Vault setup

Startup Vault, such as development mode:

```bash
vault server -dev
```

When running the dev mode be sure to declare the insecure Vault address:
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
```

Enable AppRole authentication and create our provider's role
```bash
vault auth enable approle

vault policy write admin vault-policies/admin.hcl
vault policy write user vault-policies/user.hcl

vault write -f auth/approle/role/auth-provider
vault write -f auth/approle/role/admin
vault write -f auth/approle/role/user
```

Get the `appRoleId` using
```bash
vault read auth/approle/role/auth-provider/role-id
```

Generate an `appSecretId` get getting the `secret_id` resulting from
```bash
vault write -f auth/approle/role/auth-provider/secret-id
```

When running the Spring Boot app, pass the following arguments with the specific `role-id` and
`secret-id` retrieved above.

```
--vault.authentication=APPROLE
--vault.app-role.role-id=... 
--vault.app-role.secret-id=... 
--vault-web-auth.role-mappings.admin=ADMIN
--vault-web-auth.role-mappings.user=USER
```