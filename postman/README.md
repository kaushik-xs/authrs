# Authrs Postman collection

Import `Authrs API.postman_collection.json` into Postman.

**RBAC model:**
- **Roles** are assigned **only to users** (`user_roles`).
- **Permissions** are attached to roles (`role_permissions`). A user's permissions are the union of permissions from all their roles.

## Collection variables

Set these in the collection (or environment). After **Login (email + password)** or **Login (OTP verify)**, `sessionToken` is set automatically from the response.

| Variable        | Description                          | Example / default   |
|----------------|--------------------------------------|---------------------|
| `baseUrl`      | API base URL                         | `http://localhost:3000` |
| `tenantId`     | Tenant for `X-Tenant-ID`             | `test`           |
| `sessionToken` | Bearer token (auto-set after login)  | *(empty)*           |
| `userId`       | User UUID for Admin user-role APIs   | *(set after listing users)* |
| `roleId`       | Role UUID for assign/remove role     | *(from List roles)* |
| `firstName`    | Signup / profile                     | `Jane`              |
| `lastName`     | Signup / profile                     | `Doe`               |
| `email`        | Login, signup, OTP request           | `jane@example.com`  |
| `password`     | Signup, email-password login         | `secret`            |
| `retypePassword` | Signup (must match password)       | `secret`            |
| `otpIdentifier` | OTP verify (email or phone)        | `jane@example.com`  |
| `otpCode`      | OTP verify code                      | `123456`            |
| `otpChannel`   | OTP verify channel                   | `email`             |
| `username`     | Username-password login               | *(set if using)*    |
| `provider`     | OAuth provider (e.g. google, microsoft) | `google`          |
| `groupKey`     | KV store group (admin KV APIs)        | `config`            |
| `kvKey`        | KV store key (admin KV APIs)          | `setting`           |
| `newPassword`  | New password (reset / change / admin reset) | *(set)*      |
| `resetToken`   | Token from forgot-password email      | *(paste from email)*|

**Workflow:** Set `baseUrl` and `tenantId`, then run **Signup** or **Login (email + password)**. `sessionToken` is saved automatically. For Admin routes, run **List roles** to get role UUIDs and set `userId` / `roleId` as needed.
