use std::net::IpAddr;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sqlx::PgPool;
use crate::dal::tenant::TenantRepository;
use crate::dal::tenant_payment::TenantPaymentRepository;
use crate::domain::models::tenant::CreateTenant;
use crate::domain::models::tenant_payment::CreateTenantPayment;
use chrono::Utc;
use crate::generated::auth::{
    auth_service_server::AuthService,
    AuthResponse, ChangePasswordRequest, ChangePasswordResponse, CreateTenantRequest,
    DeleteTenantRequest, DeleteTenantResponse, GetAllUsersRequest, GetAllUsersResponse,
    GetTenantRequest, GetTenantDbUrlRequest, GetTenantDbUrlResponse,
    ListTenantsRequest, ListTenantsResponse, LoginRequest, LogoutRequest,
    LogoutResponse, RefreshRequest, RegisterRequest, RevokeSessionsRequest,
    RevokeSessionsResponse, SetTenantDbUrlRequest, SetTenantDbUrlResponse,
    TenantPayload, TenantResponse, UpdateTenantRequest, UserPayload,
    ValidateRequest, ValidateResponse,
    GetUserRequest, DeleteUserRequest, DeleteUserResponse,
    UpdateUserRequest, LockUserRequest, LockUserResponse,
    CheckUsernameRequest, CheckUsernameResponse, UserDetailResponse,
    GetByUsernameRequest,
};
use crate::service::auth::{AuthError, AuthService as AuthSvc};
use crate::service::secrets::{SecretsError, TenantSecretsService};
use crate::service::user::{RegisterUserRequest, UserService, UserServiceError};

// ─── Handler ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuthGrpcHandler {
    user_service:    UserService,
    auth_service:    Arc<AuthSvc>,
    tenant_repo:     Arc<TenantRepository>,
    payment_repo:    Arc<TenantPaymentRepository>,
    secrets_svc:     Arc<TenantSecretsService>,
    pool:            Arc<PgPool>,
    app_db_url:      String,
    admin_db_url:    String,
}

impl AuthGrpcHandler {
    pub fn new(
        user_service:  UserService,
        auth_service:  Arc<AuthSvc>,
        tenant_repo:   Arc<TenantRepository>,
        payment_repo:  Arc<TenantPaymentRepository>,
        secrets_svc:   Arc<TenantSecretsService>,
        pool:          Arc<PgPool>,
        app_db_url:    String,
        admin_db_url:  String,
    ) -> Self {
        Self { user_service, auth_service, tenant_repo, payment_repo, secrets_svc, pool, app_db_url, admin_db_url }
    }
}

// ─── gRPC impl ────────────────────────────────────────────────────────────────

#[tonic::async_trait]
impl AuthService for AuthGrpcHandler {

    // ── Register ──────────────────────────────────────────────────────────────

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        debug!(email = %req.email, privat_db = req.privat_db, "register");

        // If tenant_id is provided, the admin is creating a sub-user — skip tenant provisioning.
        if !req.tenant_id.is_empty() {
            let tenant_id = Uuid::parse_str(&req.tenant_id)
                .map_err(|_| Status::invalid_argument("invalid tenant_id"))?;
            let role = parse_role(&req.role)
                .ok_or_else(|| Status::invalid_argument(format!("unknown role '{}'", req.role)))?;

            let user = self.user_service
                .register(RegisterUserRequest {
                    email:     req.email,
                    username:  req.username,
                    password:  req.password,
                    full_name: opt_str(req.full_name),
                    phone:     opt_str(req.phone),
                    role,
                    tenant_id: Some(tenant_id),
                })
                .await
                .map_err(|e| {
                    warn!(error = %e, "register sub-user failed");
                    match e {
                        UserServiceError::HashFailed                                               => Status::internal("password hashing failed"),
                        UserServiceError::Db(crate::errors::db_errors::DbError::Conflict(msg)) => Status::already_exists(msg),
                        UserServiceError::Db(e)                                                   => Status::internal(e.to_string()),
                    }
                })?;

            info!(user_id = %user.id, tenant_id = %tenant_id, "sub-user registered");
            return Ok(Response::new(AuthResponse::default()));
        }

        let (tenant_id, role) = {
            // Admin registration — auto-provisions a new tenant.
            let payment_id = opt_str(req.payment_id.clone());

            let tenant = self.tenant_repo
                .create(CreateTenant {
                    name:       req.email.clone(),
                    privat_db:  req.privat_db,
                    payment_id,
                })
                .await
                .map_err(|e| {
                    warn!(error = %e, "auto-create tenant failed on register");
                    Status::internal(e.to_string())
                })?;

            let schema_name = format!("t_{}", tenant.id.simple());

            if req.privat_db {
                // ── Private DB path ─────────────────────────────────────────
                if self.admin_db_url.is_empty() {
                    return Err(Status::failed_precondition(
                        "ARQETH_ADMIN_DB_URL is not configured — required for privat_db=true"
                    ));
                }

                let db_name     = format!("arqeth_t_{}", tenant.id.simple());
                let private_url = crate::dal::db_provisioner::replace_db_name(
                    &self.admin_db_url,
                    &db_name,
                );

                crate::dal::db_provisioner::create_private_database(
                    &self.admin_db_url,
                    &db_name,
                )
                .await
                .map_err(|e| {
                    warn!(tenant_id = %tenant.id, error = %e, "create private database failed");
                    Status::internal("failed to provision private database")
                })?;

                crate::dal::db_provisioner::init_private_db_schema(&private_url, &schema_name)
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tenant.id, error = %e, "init private db schema failed");
                        Status::internal("failed to init schema in private database")
                    })?;

                self.secrets_svc
                    .set_schema_name(tenant.id, &schema_name)
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tenant.id, error = %e, "store schema name failed");
                        Status::internal("failed to store tenant schema name")
                    })?;

                self.secrets_svc
                    .set_db_url(tenant.id, &private_url)
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tenant.id, error = %e, "store private db url failed");
                        Status::internal("failed to store private db url")
                    })?;

                info!(
                    tenant_id = %tenant.id,
                    db = %db_name,
                    schema = %schema_name,
                    "private tenant database provisioned"
                );
            } else {
                // ── Shared DB path (new schema in arqeth_db) ─────────────────
                crate::dal::schema::create_tenant_schema(&self.pool, &schema_name)
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tenant.id, error = %e, "create tenant schema failed");
                        Status::internal("failed to provision tenant schema")
                    })?;

                self.secrets_svc
                    .set_schema_name(tenant.id, &schema_name)
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tenant.id, error = %e, "store schema name failed");
                        Status::internal("failed to store tenant schema name")
                    })?;

                self.secrets_svc
                    .set_db_url(tenant.id, &self.app_db_url)
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tenant.id, error = %e, "store app db url failed");
                        Status::internal("failed to store app db url")
                    })?;

                info!(
                    tenant_id = %tenant.id,
                    schema = %schema_name,
                    "shared-db tenant schema provisioned"
                );
            }

            (Some(tenant.id), crate::domain::models::enums::UserRole::Admin)
        };

        let user = self.user_service
            .register(RegisterUserRequest {
                email:     req.email,
                username:  req.username,
                password:  req.password,
                full_name: opt_str(req.full_name),
                phone:     opt_str(req.phone),
                role,
                tenant_id,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "register failed");
                match e {
                    UserServiceError::HashFailed                                               => Status::internal("password hashing failed"),
                    UserServiceError::Db(crate::errors::db_errors::DbError::Conflict(msg)) => Status::already_exists(msg),
                    UserServiceError::Db(e)                                                   => Status::internal(e.to_string()),
                }
            })?;

        info!(user_id = %user.id, "user registered");

        // Persist payment record for admin registrations that came through a paid plan.
        if !req.payment_id.is_empty() {
            if let Some(tid) = tenant_id {
                let plan_end = match req.billing_period.as_str() {
                    "yearly" => Some(Utc::now() + chrono::Duration::days(365)),
                    _        => Some(Utc::now() + chrono::Duration::days(30)),
                };
                let method = if req.payment_method.is_empty() {
                    "card".to_string()
                } else {
                    req.payment_method.clone()
                };

                self.payment_repo
                    .create(CreateTenantPayment {
                        tenant_id:        tid,
                        payment_id:       req.payment_id.clone(),
                        payment_method:   method,
                        payment_plan:     req.payment_plan.clone(),
                        payment_plan_end: plan_end,
                    })
                    .await
                    .map_err(|e| {
                        warn!(tenant_id = %tid, error = %e, "persist tenant_payment failed");
                        Status::internal(e.to_string())
                    })?;

                info!(tenant_id = %tid, payment_id = %req.payment_id, "tenant_payment recorded");
            }
        }

        Ok(Response::new(AuthResponse::default()))
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        debug!(email = %req.email, "login");

        let ip         = req.ip_address.parse::<IpAddr>().ok();
        let device_hint = opt_str(req.device_hint);
        let user_agent  = opt_str(req.user_agent);

        let result = self.auth_service
            .login(&req.email, &req.password, device_hint, ip, user_agent)
            .await
            .map_err(auth_to_status)?;

        Ok(Response::new(AuthResponse {
            access_token:      result.access_token,
            refresh_jti:       result.refresh_jti.to_string(),
            expires_in:        result.expires_in,
            db_connection_url: result.db_connection_url.unwrap_or_default(),
            user: Some(UserPayload {
                user_id:      result.access_claims.sub.to_string(),
                email:        result.access_claims.email,
                username:     result.access_claims.username,
                role:         result.access_claims.role.to_string(),
                status:       result.user_status.to_string(),
                tenant_id:    result.access_claims.tenant_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                full_name:    String::new(),
                locked_until: String::new(),
            }),
        }))
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let req = request.into_inner();
        debug!(refresh_jti = %req.refresh_jti, "logout");

        let access = opt_str(req.access_token);

        self.auth_service
            .logout(&req.refresh_jti, access.as_deref())
            .await
            .map_err(auth_to_status)?;

        Ok(Response::new(LogoutResponse { success: true }))
    }

    // ── Refresh token ─────────────────────────────────────────────────────────

    async fn refresh_token(
        &self,
        request: Request<RefreshRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        debug!(refresh_jti = %req.refresh_jti, "refresh_token");

        let result = self.auth_service
            .refresh_token(&req.refresh_jti, opt_str(req.device_hint))
            .await
            .map_err(auth_to_status)?;

        Ok(Response::new(AuthResponse {
            access_token:      result.access_token,
            refresh_jti:       result.refresh_jti.to_string(),
            expires_in:        result.expires_in,
            db_connection_url: result.db_connection_url.unwrap_or_default(),
            user: Some(UserPayload {
                user_id:      result.access_claims.sub.to_string(),
                email:        result.access_claims.email,
                username:     result.access_claims.username,
                role:         result.access_claims.role.to_string(),
                status:       result.user_status.to_string(),
                tenant_id:    result.access_claims.tenant_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                full_name:    String::new(),
                locked_until: String::new(),
            }),
        }))
    }

    // ── Validate token ────────────────────────────────────────────────────────

    async fn validate_token(
        &self,
        request: Request<ValidateRequest>,
    ) -> Result<Response<ValidateResponse>, Status> {
        let req = request.into_inner();
        debug!("validate_token");

        match self.auth_service.validate_token(&req.access_token).await {
            Ok(claims) => Ok(Response::new(ValidateResponse {
                valid: true,
                user: Some(UserPayload {
                    user_id:      claims.sub.to_string(),
                    email:        claims.email,
                    username:     claims.username,
                    role:         claims.role.to_string(),
                    status:       String::new(),
                    tenant_id:    claims.tenant_id
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                    full_name:    String::new(),
                    locked_until: String::new(),
                }),
                error: String::new(),
            })),
            Err(e) => {
                warn!(error = %e, "validate_token rejected");
                Ok(Response::new(ValidateResponse {
                    valid: false,
                    user:  None,
                    error: e.to_string(),
                }))
            }
        }
    }

    // ── Revoke sessions ───────────────────────────────────────────────────────

    async fn revoke_sessions(
        &self,
        request: Request<RevokeSessionsRequest>,
    ) -> Result<Response<RevokeSessionsResponse>, Status> {
        let req = request.into_inner();
        debug!(user_id = %req.user_id, "revoke_sessions");

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let count = self.auth_service
            .revoke_sessions(user_id)
            .await
            .map_err(auth_to_status)?;

        Ok(Response::new(RevokeSessionsResponse {
            sessions_revoked: count as u32,
        }))
    }

    // ── Change password ───────────────────────────────────────────────────────

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let req = request.into_inner();
        debug!(user_id = %req.user_id, "change_password");

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let sessions_revoked = self.auth_service
            .change_password(
                user_id,
                &req.current_password,
                &req.new_password,
                req.revoke_sessions,
            )
            .await
            .map_err(auth_to_status)?;

        Ok(Response::new(ChangePasswordResponse {
            success:          true,
            sessions_revoked: sessions_revoked as u32,
        }))
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    async fn get_all_users(
        &self,
        request: Request<GetAllUsersRequest>,
    ) -> Result<Response<GetAllUsersResponse>, Status> {
        let req = request.into_inner();
        debug!(limit = req.limit, offset = req.offset, "get_all_users");

        let tenant_filter = if req.tenant_id.is_empty() {
            None
        } else {
            Some(Uuid::parse_str(&req.tenant_id)
                .map_err(|_| Status::invalid_argument("invalid tenant_id"))?)
        };

        let users = self.user_service
            .list_all(req.limit as i64, req.offset as i64, tenant_filter)
            .await
            .map_err(|e| {
                error!(error = %e, "get_all_users failed");
                Status::internal(e.to_string())
            })?;

        let total   = users.len() as i32;
        let payload = users.into_iter().map(|u| UserPayload {
            user_id:      u.id.to_string(),
            email:        u.email,
            username:     u.username,
            role:         u.role.to_string(),
            status:       u.status.to_string(),
            tenant_id:    u.tenant_id.map(|id| id.to_string()).unwrap_or_default(),
            full_name:    u.full_name.unwrap_or_default(),
            locked_until: u.locked_until.map(|t| t.to_rfc3339()).unwrap_or_default(),
        }).collect();

        info!(total, "get_all_users completed");
        Ok(Response::new(GetAllUsersResponse { users: payload, total }))
    }

    // ── Tenants ───────────────────────────────────────────────────────────────

    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<TenantResponse>, Status> {
        let req = request.into_inner();
        debug!(name = %req.name, "create_tenant");

        let tenant = self.tenant_repo
            .create(CreateTenant { name: req.name, privat_db: false, payment_id: None })
            .await
            .map_err(|e| { warn!(error = %e, "create_tenant failed"); Status::internal(e.to_string()) })?;

        info!(tenant_id = %tenant.id, "tenant created");
        Ok(Response::new(tenant_to_response(tenant)))
    }

    async fn get_tenant(
        &self,
        request: Request<GetTenantRequest>,
    ) -> Result<Response<TenantResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.tenant_id)
            .map_err(|_| Status::invalid_argument("invalid tenant_id"))?;

        let tenant = self.tenant_repo.find_by_id(id).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(tenant_to_response(tenant)))
    }

    async fn update_tenant(
        &self,
        request: Request<UpdateTenantRequest>,
    ) -> Result<Response<TenantResponse>, Status> {
        let req = request.into_inner();
        let id     = Uuid::parse_str(&req.tenant_id)
            .map_err(|_| Status::invalid_argument("invalid tenant_id"))?;
        let name   = opt_str(req.name);
        let status = match req.status.as_str() {
            ""         => None,
            "active"   => Some(crate::domain::models::enums::UserStatus::Active),
            "inactive" => Some(crate::domain::models::enums::UserStatus::Inactive),
            "banned"   => Some(crate::domain::models::enums::UserStatus::Banned),
            "pending"  => Some(crate::domain::models::enums::UserStatus::Pending),
            _          => return Err(Status::invalid_argument("invalid status")),
        };

        let tenant = self.tenant_repo.update(id, name, status).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(tenant_to_response(tenant)))
    }

    async fn delete_tenant(
        &self,
        request: Request<DeleteTenantRequest>,
    ) -> Result<Response<DeleteTenantResponse>, Status> {
        let req = request.into_inner();
        let id  = Uuid::parse_str(&req.tenant_id)
            .map_err(|_| Status::invalid_argument("invalid tenant_id"))?;

        self.tenant_repo.soft_delete(id).await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(tenant_id = %id, "tenant deleted");
        Ok(Response::new(DeleteTenantResponse { success: true }))
    }

    async fn list_tenants(
        &self,
        request: Request<ListTenantsRequest>,
    ) -> Result<Response<ListTenantsResponse>, Status> {
        let req     = request.into_inner();
        let tenants = self.tenant_repo
            .list_active(req.limit as i64, req.offset as i64)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let total   = tenants.len() as i32;
        let payload = tenants.into_iter().map(|t| TenantPayload {
            tenant_id:  t.id.to_string(),
            name:       t.name,
            status:     t.status.to_string(),
            created_at: t.created_at.to_string(),
        }).collect();

        Ok(Response::new(ListTenantsResponse { tenants: payload, total }))
    }

    // ── User admin ────────────────────────────────────────────────────────────

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<UserDetailResponse>, Status> {
        let req = request.into_inner();
        let id  = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let u = self.user_service.get_user(id).await
            .map_err(|e| match e {
                UserServiceError::Db(crate::errors::db_errors::DbError::NotFound) => Status::not_found("user not found"),
                e => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(user_to_detail(u)))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = request.into_inner();
        let id  = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        self.user_service.delete_user(id).await
            .map_err(|e| match e {
                UserServiceError::Db(crate::errors::db_errors::DbError::NotFound) => Status::not_found("user not found"),
                e => Status::internal(e.to_string()),
            })?;

        info!(user_id = %id, "user deleted");
        Ok(Response::new(DeleteUserResponse { success: true }))
    }

    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<UserDetailResponse>, Status> {
        use crate::domain::models::user::UpdateUser;

        let req = request.into_inner();
        let id  = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let role = if req.role.is_empty() {
            None
        } else {
            Some(parse_role(&req.role)
                .ok_or_else(|| Status::invalid_argument(format!("unknown role '{}'", req.role)))?)
        };

        let status = match req.status.as_str() {
            ""         => None,
            "active"   => Some(crate::domain::models::enums::UserStatus::Active),
            "inactive" => Some(crate::domain::models::enums::UserStatus::Inactive),
            "banned"   => Some(crate::domain::models::enums::UserStatus::Banned),
            "pending"  => Some(crate::domain::models::enums::UserStatus::Pending),
            _          => return Err(Status::invalid_argument("invalid status")),
        };

        let dto = UpdateUser {
            full_name: opt_str(req.full_name),
            phone:     opt_str(req.phone),
            role,
            status,
        };

        let u = self.user_service.update_user(id, dto).await
            .map_err(|e| match e {
                UserServiceError::Db(crate::errors::db_errors::DbError::NotFound) => Status::not_found("user not found"),
                e => Status::internal(e.to_string()),
            })?;

        info!(user_id = %id, "user updated");
        Ok(Response::new(user_to_detail(u)))
    }

    async fn lock_user(
        &self,
        request: Request<LockUserRequest>,
    ) -> Result<Response<LockUserResponse>, Status> {
        let req = request.into_inner();
        let id  = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let until = self.user_service.lock_user(id, req.lock, req.minutes).await
            .map_err(|e| match e {
                UserServiceError::Db(crate::errors::db_errors::DbError::NotFound) => Status::not_found("user not found"),
                e => Status::internal(e.to_string()),
            })?;

        let locked_until = until.map(|t| t.to_rfc3339()).unwrap_or_default();
        info!(user_id = %id, lock = req.lock, "user lock toggled");
        Ok(Response::new(LockUserResponse { success: true, locked_until }))
    }

    async fn get_user_by_username(
        &self,
        request: Request<GetByUsernameRequest>,
    ) -> Result<Response<UserDetailResponse>, Status> {
        let req = request.into_inner();
        if req.username.is_empty() {
            return Err(Status::invalid_argument("username required"));
        }

        let u = self.user_service.get_user_by_username(&req.username).await
            .map_err(|e| match e {
                UserServiceError::Db(crate::errors::db_errors::DbError::NotFound) => Status::not_found("user not found"),
                e => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(user_to_detail(u)))
    }

    async fn check_username(
        &self,
        request: Request<CheckUsernameRequest>,
    ) -> Result<Response<CheckUsernameResponse>, Status> {
        let req = request.into_inner();
        if req.username.is_empty() {
            return Err(Status::invalid_argument("username required"));
        }

        let available = self.user_service.check_username(&req.username).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CheckUsernameResponse { available }))
    }

    // ── Tenant Secrets ────────────────────────────────────────────────────────

    async fn set_tenant_db_url(
        &self,
        request: Request<SetTenantDbUrlRequest>,
    ) -> Result<Response<SetTenantDbUrlResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|_| Status::invalid_argument("invalid tenant_id"))?;
        debug!(tenant_id = %tenant_id, "set_tenant_db_url");

        self.secrets_svc
            .set_db_url(tenant_id, &req.db_connection_url)
            .await
            .map_err(secrets_to_status)?;

        Ok(Response::new(SetTenantDbUrlResponse { success: true }))
    }

    async fn get_tenant_db_url(
        &self,
        request: Request<GetTenantDbUrlRequest>,
    ) -> Result<Response<GetTenantDbUrlResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|_| Status::invalid_argument("invalid tenant_id"))?;
        debug!(tenant_id = %tenant_id, "get_tenant_db_url");

        let url = self.secrets_svc
            .get_db_url(tenant_id)
            .await
            .map_err(secrets_to_status)?;

        Ok(Response::new(GetTenantDbUrlResponse { db_connection_url: url }))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Proto3 strings are never null but may be empty — treat empty as absent.
fn opt_str(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

fn auth_to_status(e: AuthError) -> Status {
    match e {
        AuthError::InvalidCredentials     => Status::unauthenticated("invalid credentials"),
        AuthError::AccountLocked(until)   => Status::permission_denied(
            format!("account locked until {until}")
        ),
        AuthError::AccountInactive        => Status::permission_denied("account is not active"),
        AuthError::InvalidToken           => Status::unauthenticated("token invalid or expired"),
        AuthError::TokenRevoked           => Status::unauthenticated("token has been revoked"),
        AuthError::SessionNotFound        => Status::not_found("session not found"),
        AuthError::BadUuid(msg)           => Status::invalid_argument(msg),
        e => {
            error!(error = %e, "auth internal error");
            Status::internal("internal error")
        }
    }
}

fn tenant_to_response(t: crate::domain::models::tenant::Tenant) -> TenantResponse {
    TenantResponse {
        tenant_id:  t.id.to_string(),
        name:       t.name,
        status:     t.status.to_string(),
        created_at: t.created_at.to_string(),
    }
}

fn parse_role(s: &str) -> Option<crate::domain::models::enums::UserRole> {
    use crate::domain::models::enums::UserRole;
    match s.to_lowercase().as_str() {
        "admin"      => Some(UserRole::Admin),
        "user"       => Some(UserRole::User),
        "moderator"  => Some(UserRole::Moderator),
        "arquitecto" => Some(UserRole::Arquitecto),
        "finanzas"   => Some(UserRole::Finanzas),
        "reportes"   => Some(UserRole::Reportes),
        _            => None,
    }
}

fn user_to_detail(u: crate::domain::models::user::User) -> UserDetailResponse {
    UserDetailResponse {
        user_id:         u.id.to_string(),
        email:           u.email,
        username:        u.username,
        full_name:       u.full_name.unwrap_or_default(),
        phone:           u.phone.unwrap_or_default(),
        role:            u.role.to_string(),
        status:          u.status.to_string(),
        tenant_id:       u.tenant_id.map(|id| id.to_string()).unwrap_or_default(),
        last_login_at:   u.last_login_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
        failed_attempts: u.failed_attempts as i32,
        locked_until:    u.locked_until.map(|t| t.to_rfc3339()).unwrap_or_default(),
        created_at:      u.created_at.to_rfc3339(),
    }
}

fn secrets_to_status(e: SecretsError) -> Status {
    match e {
        SecretsError::NotFound   => Status::not_found("tenant secret not found"),
        SecretsError::Utf8       => Status::internal("secret contains invalid UTF-8"),
        SecretsError::Encryption(e) => {
            error!(error = %e, "encryption error");
            Status::internal("encryption error")
        }
        SecretsError::Db(e) => {
            error!(error = %e, "secrets db error");
            Status::internal("internal error")
        }
    }
}
