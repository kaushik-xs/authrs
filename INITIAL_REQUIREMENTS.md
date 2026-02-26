Below is the Final Consolidated Requirement Document for your Rust-based, Multi-Tenant Authentication Service, incorporating:
	•	✅ Email/Password
	•	✅ Email OTP
	•	✅ Mobile OTP (SMS)
	•	✅ Mobile OTP (WhatsApp)
	•	✅ Username/Password (username-only users allowed)
	•	✅ Google & Microsoft OAuth (tenant-specific)
	•	✅ RBAC (Groups, Roles, Permissions)
	•	✅ MFA (TOTP + backup codes)
	•	✅ Redis-backed session management (50k+ concurrent sessions)
	•	✅ Multi-tenant isolation
	•	✅ Group-specific login method enforcement
	•	✅ Username-only account support

⸻

📘 Authentication Service – Final Requirement Document (vFinal)

⸻

1️⃣ System Overview

1.1 Purpose

The Authentication Service is a multi-tenant, high-scale identity and access management API written in Rust. It provides:
	•	Authentication
	•	Authorization (RBAC)
	•	Session management
	•	MFA
	•	OAuth integration
	•	OTP via Email, SMS, and WhatsApp

It is a stateless horizontally scalable API service, using Redis for active session storage.

⸻

2️⃣ Architecture Overview

2.1 High-Level Architecture

Client
   ↓
Load Balancer
   ↓
Auth Service (Multiple Rust Pods)
   ↓
Redis Cluster (Sessions, OTP, Rate Limit)
   ↓
PostgreSQL Cluster


⸻

2.2 Technology Stack

Layer	Technology
Language	Rust
Web Framework	axum
Database	PostgreSQL
ORM	sqlx
Cache & Sessions	Redis Cluster
Password Hashing	Argon2id
MFA	TOTP (RFC 6238)
OAuth	Google & Microsoft
Observability	Prometheus + Structured Logging


⸻

3️⃣ Multi-Tenant Design

⸻

3.1 Tenant Isolation

Every core table must include:

tenant_id UUID NOT NULL

Tenant resolution methods (configurable):
	•	X-Tenant-ID header (primary)
	•	Subdomain resolution
	•	Path prefix

All data operations are scoped by tenant_id.

⸻

3.2 Tenant-Level Configuration

Each tenant can configure:
	•	Supported login methods
	•	OAuth credentials
	•	MFA policies
	•	Password policy
	•	Session timeout
	•	Rate limits
	•	Account lock policy
	•	WhatsApp/SMS providers

⸻

4️⃣ Identity Model

⸻

4.1 Supported Login Methods

ID	Method
1	Email + Password
2	Email + OTP
3	Mobile + OTP (SMS)
4	Username + Password
5	OAuth (Google, Microsoft)
6	Mobile + OTP (WhatsApp)


⸻

4.2 User Identity Types

1. Full Identity

Email + Mobile + Username (any combination)

2. Contact-Based

Email OR Mobile

3. Username-Only
	•	Username required
	•	Password required
	•	Email = NULL
	•	Mobile = NULL

⸻

4.3 Identity Validation Rule

At least one must exist:

email
OR
(mobile AND country_code)
OR
username


⸻

4.4 Username-Only Constraints
	•	Cannot use OTP login
	•	Cannot use email-based reset
	•	Can use TOTP MFA
	•	Recommended: MFA mandatory

⸻

5️⃣ Database Schema (Core Tables)

⸻

tenants

id UUID PRIMARY KEY
name VARCHAR UNIQUE
status VARCHAR
created_at TIMESTAMP


⸻

users

id UUID PRIMARY KEY
tenant_id UUID REFERENCES tenants(id)

email VARCHAR NULL
username VARCHAR NULL
mobile VARCHAR NULL
country_code VARCHAR(5) NULL

password_hash TEXT NULL

status VARCHAR
mfa_enabled BOOLEAN
failed_attempts INT
locked_until TIMESTAMP

created_at TIMESTAMP
updated_at TIMESTAMP

CHECK (
  email IS NOT NULL OR
  (mobile IS NOT NULL AND country_code IS NOT NULL) OR
  username IS NOT NULL
)

UNIQUE (tenant_id, email)
UNIQUE (tenant_id, username)
UNIQUE (tenant_id, mobile, country_code)


⸻

groups

id UUID
tenant_id UUID
name VARCHAR
supported_login_methods INT[]


⸻

user_groups

user_id UUID
group_id UUID


⸻

roles

id UUID
tenant_id UUID
name VARCHAR


⸻

permissions

id UUID
tenant_id UUID
name VARCHAR


⸻

role_permissions

role_id UUID
permission_id UUID


⸻

group_roles

group_id UUID
role_id UUID


⸻

oauth_providers (tenant-specific)

id UUID
tenant_id UUID
provider VARCHAR  -- google | microsoft
client_id TEXT
client_secret TEXT
redirect_url TEXT


⸻

otp_codes

id UUID
tenant_id UUID
identifier VARCHAR
channel VARCHAR -- email | sms | whatsapp
code VARCHAR
purpose VARCHAR
expires_at TIMESTAMP
attempt_count INT


⸻

sessions (Audit)

id UUID
tenant_id UUID
user_id UUID
session_id VARCHAR
ip_address TEXT
user_agent TEXT
expires_at TIMESTAMP
created_at TIMESTAMP
revoked BOOLEAN


⸻

Redis Active Session Structure

Key:

session:{session_id}

Value:

{
  tenant_id,
  user_id,
  roles,
  ip,
  user_agent,
  expires_at
}


⸻

6️⃣ Session Management (Option B – Redis-Based)

⸻

6.1 Session Token
	•	Random UUID
	•	Sent as:

Authorization: Bearer <session_id>


⸻

6.2 Session Policies
	•	Idle timeout (configurable)
	•	Absolute timeout
	•	Sliding expiration supported
	•	Logout current
	•	Logout all
	•	Revoke by admin

⸻

6.3 Scalability Requirement
	•	50,000+ concurrent sessions
	•	Redis cluster required
	•	Session validation < 50ms

⸻

7️⃣ Login Flow Logic

⸻

7.1 Login Method Validation

Effective Login Methods =

Intersection(
  tenant_allowed_methods,
  group_allowed_methods,
  user_supported_methods
)

Reject if requested method not in final set.

⸻

7.2 Account Lock Policy
	•	Lock after N failed attempts
	•	Lock duration configurable
	•	Reset counter after successful login

⸻

8️⃣ OTP System

⸻

8.1 Supported Channels
	•	Email
	•	SMS
	•	WhatsApp

⸻

8.2 OTP Rules
	•	6-digit code
	•	Expiry: 5 minutes
	•	Max attempts: 5
	•	Per-identifier rate limiting
	•	Store channel and delivery status

⸻

8.3 WhatsApp Requirements
	•	Support WhatsApp Business API abstraction
	•	Tenant-level provider configuration
	•	Fallback optional

⸻

9️⃣ OAuth Support

Supported Providers:
	•	Google
	•	Microsoft

Each tenant must configure:
	•	client_id
	•	client_secret
	•	redirect_url

OAuth must validate:
	•	state parameter
	•	ID token signature
	•	issuer
	•	audience

⸻

🔟 MFA (Multi-Factor Authentication)

⸻

10.1 Supported MFA Types

Type	Supported
TOTP (Authenticator App)	✅
Backup Codes	✅
SMS-based MFA	Future
WhatsApp MFA	Future


⸻

10.2 MFA Flow
	1.	Primary login success
	2.	If MFA enabled → return MFA_REQUIRED
	3.	Validate TOTP
	4.	Issue session

⸻

11️⃣ RBAC Model

⸻

User → Groups → Roles → Permissions

Permissions are string-based:

user:create
user:read
admin:all

Authorization middleware:
	1.	Validate session
	2.	Fetch roles (cached)
	3.	Validate permission
	4.	Allow / Reject

⸻

12️⃣ APIs (Tenant Scoped)

All APIs require:

X-Tenant-ID


⸻

Authentication APIs
	•	POST /login/email-password
	•	POST /login/username-password
	•	POST /login/email-otp/request
	•	POST /login/mobile-otp/request
	•	POST /login/mobile-whatsapp-otp/request
	•	POST /login/otp/verify
	•	GET /oauth/{provider}
	•	GET /oauth/{provider}/callback

⸻

MFA APIs
	•	POST /mfa/enable
	•	POST /mfa/verify
	•	POST /mfa/validate

⸻

Session APIs
	•	GET /session/validate
	•	POST /logout
	•	POST /logout/all

⸻

Admin APIs
	•	POST /admin/users
	•	POST /admin/groups
	•	POST /admin/roles
	•	POST /admin/permissions
	•	POST /admin/groups/{id}/roles
	•	POST /admin/groups/{id}/users

⸻

13️⃣ Security Requirements
	•	Argon2id password hashing
	•	Strong password policy configurable
	•	IP rate limiting
	•	Identifier rate limiting
	•	CSRF protection for OAuth
	•	Redis-based sliding window rate limiter
	•	Device fingerprint logging
	•	Audit logging for:
	•	Login
	•	Logout
	•	MFA changes
	•	Role changes
	•	Failed attempts

⸻

14️⃣ Performance Requirements
	•	50,000+ concurrent sessions
	•	10k login requests/minute
	•	P95 login < 200ms
	•	P95 session validation < 50ms
	•	Horizontal scaling
	•	Zero-downtime deployment

⸻

15️⃣ Observability

Must expose:
	•	/health
	•	/metrics
	•	Prometheus counters:
	•	login_success_total
	•	login_failure_total
	•	otp_sent_total
	•	active_sessions_total
	•	mfa_enabled_total

Structured JSON logging required.

⸻

16️⃣ Edge Cases Covered
	•	Username-only users
	•	Tenant-specific login method restriction
	•	Group-specific login method restriction
	•	OAuth-only accounts
	•	Contact-less accounts
	•	Account lockout
	•	OTP brute force
	•	Session hijack prevention

⸻

17️⃣ Future Enhancements (Not in Scope)
	•	WebAuthn / Passkeys
	•	SAML
	•	Risk-based authentication
	•	Geo anomaly detection
	•	Device trust scoring
	•	Adaptive MFA

⸻

18️⃣ Final Summary

This authentication service is:
	•	Multi-tenant
	•	Horizontally scalable
	•	Redis-session based
	•	WhatsApp OTP enabled
	•	Enterprise RBAC-ready
	•	OAuth-integrated
	•	MFA-capable
	•	Username-only compatible
	•	Designed for 50k+ concurrent sessions

⸻

If you would like next, I can provide:
	•	🔹 Complete OpenAPI 3.1 specification (Swagger YAML)
	•	🔹 Production-grade Rust folder structure
	•	🔹 Redis key design blueprint
	•	🔹 Threat model analysis
	•	🔹 Capacity planning for 100k sessions
	•	🔹 Clean Architecture blueprint tailored for your Rust ecosystem