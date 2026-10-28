# Threat model — Nextcloud Server (github.com/cx-benchmark/server, master)

## system

Nextcloud Server 36.0.0 dev (`version.php`: `$OC_VersionString = '36.0.0 dev'`, `$OC_Channel = 'git'`): a self-hosted PHP server where users store, sync and share files, calendars and contacts (README.md), usually reachable from the internet, multi-user inside one instance, and federating with other instances over OCM. Not a library: the attack surface is HTTP (web UI, OCS REST, WebDAV/CalDAV/CardDAV), background jobs, outbound HTTP, and the `occ` CLI.

Main components (paths from repo root):
- Front controllers: `index.php` (AppFramework routes, installer), `remote.php` (DAV via `apps/dav/appinfo/v1|v2/*.php`), `public.php` (share-token DAV), `ocs/v1.php` / `ocs/v2.php` (OCS), `status.php`, `cron.php`, `ocs-provider/index.php`, `console.php` / `occ` (CLI). Bootstrap in `lib/OC.php` (`OC::boot`, `OC::initForRequest`, `OC::handleRequest`, `OC::handleLogin`).
- `lib/private` (implementation: auth, sessions, files/VFS, sharing, HTTP client, security), `lib/public` (OCP API for apps), `lib/unstable` (NCU experimental API, e.g. unified sharing).
- `core/`: core controllers (`core/Controller`, routes by `#[FrontpageRoute]`/`#[ApiRoute]` attributes plus `core/routes.php`), templates, frontend sources, `core/shipped.json`.
- `apps/`: 34 bundled app directories. `core/shipped.json` marks always-enabled: appstore, cloud_federation_api, dav, federatedfilesharing, files, lookup_server_connector, oauth2, profile, provisioning_api, settings, sharing, theming, twofactor_backupcodes, viewer, workflowengine; default-enabled (of those in this repo) adds comments, contactsinteraction, dashboard, federation, files_reminders, files_sharing, files_trashbin, files_versions, sharebymail, systemtags, updatenotification, user_status, weather_status, webhook_listeners. In repo but not default-enabled: admin_audit, encryption, files_external, user_ldap, testing (testing is not in `shippedApps` and is removed from releases by `.nextcloudignore`).
- `dist/`: compiled frontend bundles (built by `build/demi.sh` per `package.json` scripts, committed; CI `node-dist-unchanged.yml` checks them).
- `3rdparty/`: git submodule (`.gitmodules` → nextcloud/3rdparty) holding composer PHP dependencies (Sabre DAV, Symfony, Guzzle, phpseclib, firebase/php-jwt …); loaded by `OC::boot` from `3rdparty/autoload.php`. Empty in this checkout: out of view.

Principals the code distinguishes:
- admin: member of group `admin` (`IGroupManager::isAdmin`), checked in `SecurityMiddleware::isAdminUser`.
- delegated admin: groups authorized for a settings class (`OC\Settings\AuthorizedGroupMapper`, `#[AuthorizedAdminSetting]`).
- subadmin: group-scoped (`ISubAdmin`).
- user: password / app password / session.
- public link recipient: share token plus optional share password.
- federated peers: trusted servers with a shared secret (`apps/federation`), OCM peers, optionally HTTP-signed.
- ExApps: via AppAPI, `AUTHORIZATION-APP-API` header checked in `OC::tryAppAPILogin` by `OCA\AppAPI\Service\AppAPIService` (app_api is not in this repo: out of view).
- CLI operator: `console.php` exits unless the process uid equals the owner of `config/config.php`.

Build, ship, deploy per the repo's own files:
- Release packaging is not in this repo (no release workflow in `.github/workflows`). `.nextcloudignore` ("Files removed at build time") lists what releases drop: tests, `/build`, `/apps/testing`, `/.devcontainer`, `/vendor-bin`, `/config/config.php`, `/Caddyfile`, `/openapi.json`, `/autotest*.sh`, docs and linters.
- Web server: Apache via the shipped `.htaccess`. It rewrites `.well-known` and `ocm-provider` to `index.php`, returns 404 for `^(?:build|tests|config|lib|3rdparty|templates)/` and `^(?:\.(?!well-known)|autotest|occ|issue|indie|db_|console)`, and sets fallback security headers. `.user.ini` is also shipped.
- `Caddyfile` (FrankenPHP worker mode, handled by `OC::handleRequests`) says "THIS IS AN EXPERIMENTAL FEATURE / DO NOT USE THIS IN PRODUCTION". No nginx config in the repo.
- Configuration: `config/config.php` plus `config/*.config.php` (`lib/private/Config.php`, glob), with `NC_`-prefixed environment variables overriding values (`Config::ENV_PREFIX`). The config dir can be moved with env `NEXTCLOUD_CONFIG_DIR` (`OC::boot`). `config/config.sample.php` is documentation only.

Request pipeline, as read in `lib/OC.php`:
- `boot`: `libxml_set_external_entity_loader` returns null.
- `initForRequest`:
  - session init: cookie `httponly`; `secure` when the protocol is https; name = instance id; contents encrypted by `OC\Session\CryptoWrapper` with the `oc_sessionPassphrase` cookie.
  - legacy CSP header (`addSecurityHeaders`).
  - `performSameSiteCookieProtection`.
  - user backends set up.
  - trusted-domain check (`TrustedDomainHelper`) answers 400 for untrusted Host, except `/css/` paths.
- `handleRequest`:
  - not installed → `SetupController::run($_POST)`.
  - maintenance / upgrade pages.
  - `handleLogin`, skipped for `/apps/oauth2/api/v1/token` and for requests carrying `X-Nextcloud-Federation`.
  - `Router::match`.
- AppFramework middleware order (`DIContainer` `MiddlewareDispatcher`): Compression, NotModified, SameSiteCookie, CORS, OCS, InvalidParameter, Security, CSP, FeaturePolicy, PasswordConfirmation, TwoFactor (`core/Middleware/TwoFactorMiddleware.php`), BruteForce, RateLimiting, PublicShare, AdditionalScripts, then app-registered middleware, then Session.

## adversaries

Counts below come from an attribute scan of public methods in `apps/*/lib/Controller`, `core/Controller` and `lib/public/AppFramework` controllers, not tests. Every anonymous AppFramework entry point and every anonymous non-AppFramework script is listed. Left out are about 400 controller methods that require a login:
- about 270 marked `#[NoAdminRequired]`, of which only the main groups are named below;
- 46 `#[AuthorizedAdminSetting]`;
- about 73 admin-only by default;
- 12 `#[ExAppRequired]` (all in `core/Controller/TaskProcessingApiController.php`).

They are registered in `apps/*/appinfo/routes.php` (254 route entries) and in `#[ApiRoute]`/`#[FrontpageRoute]` attributes (220) in `apps/*/lib/Controller/*.php` and `core/Controller/*.php`. DAV collections are in `apps/dav/lib/RootCollection.php`; occ commands in `core/register_command.php` and each app's `appinfo/info.xml` `<commands>`.

URL forms (`lib/private/AppFramework/Routing/RouteParser.php`):
- web routes: `/index.php/apps/<app>/<url>`; core routes and a `root` override only for apps in `RouteParser::rootUrlApps` (appstore, cloud_federation_api, core, files_sharing, files, profile, settings, …).
- OCS routes: `/ocs/v2.php/apps/<app>/<url>` (also `v1.php`); any app may set `root`.

Application-wide default: `SecurityMiddleware::beforeController` requires a logged-in admin, a CSRF token and the strict SameSite cookie for every AppFramework method. A method opts out with:
- `#[PublicPage]`: no login; app need not be enabled for the user.
- `#[NoAdminRequired]`: any logged-in user.
- `#[SubAdminRequired]` / `#[AuthorizedAdminSetting]`.
- `#[NoCSRFRequired]`: no CSRF token and no strict-cookie check.
- `#[ExAppRequired]`: session `app_api` must be true.

Annotations in docblocks (`@PublicPage` …) count the same (`ControllerMethodReflector::hasAnnotationOrAttribute`); class-level attributes are not read. For `#[AuthorizedAdminSetting]`, `#[SubAdminRequired]` and admin-default methods, `IRemoteAddress::allowsAdminActions` (`allowed_admin_ranges`) is also enforced. App middleware tightens this for its own controllers:
- `ProvisioningApiMiddleware` (provisioning_api) and `SubadminMiddleware` (settings) require admin or subadmin unless the method has `#[NoSubAdminRequired]` or `#[AuthorizedAdminSetting]`.
- `ShareApiEnabledMiddleware` (sharing) answers 501 unless system config `sharing.unified_api_enable` is true (`SharingManager::isApiEnabled`; default false).

### Anonymous network client

Reaches the following without credentials.

Non-AppFramework scripts:
- `index.php` before install: `SetupController::run` takes DB and admin credentials from `$_POST`. The only gate is that `config/CAN_INSTALL` exists (`Setup::canInstallFileExists`); this file is committed in `config/`.
- `status.php`: JSON with installed, maintenance, version, productname. Sends `Access-Control-Allow-Origin: *`; no session.
- `cron.php` over HTTP: `CronService::runWeb` runs the next background job unless appconfig `core.backgroundjobs_mode` is `cron` (default `ajax`, `CronService::run`). Exempt from the SameSite strict check (`OC::performSameSiteCookieProtection`).
- `ocs-provider/index.php`: `OC\OCS\Provider::buildProviderList`; no auth check in the file.
- `/index.php/heartbeat`: returns early (`OC::handleRequest`).
- `remote.php` (`apps/dav/lib/Server.php`):
  - `AnonymousOptionsPlugin` answers OPTIONS/HEAD from a "Microsoft Office" User-Agent with empty Authorization against a fake tree, before auth.
  - `OCA\DAV\DAV\PublicAuth` authenticates any path starting with `public-calendars` or `principals/system/public` as `principals/system/public` (published calendars, `PublicCalendarRoot`).
  - `/remote.php/direct/<token>` (`apps/dav/appinfo/v2/direct.php`, `DirectMapper` tokens, `IThrottler`).
  - Unknown service names resolve through appconfig `core.remote_<service>` (`remote.php resolveService`).
- `public.php/dav/files/<token>/…` (`apps/dav/appinfo/v2/publicremote.php`) and `public.php/webdav` (v1; token as Basic user, `LegacyPublicAuth`): see the next adversary.

Core web routes (`/index.php/…`):
- Login: `GET /login` and `POST /login` (`LoginController::tryLogin`, `#[NoCSRFRequired]`, `#[BruteForceProtection]`); `POST /login/webauthn/start|finish` (CSRF required).
- Login flow v1: `GET /login/flow`, `POST /login/flow/apptoken`.
- Login flow v2: `POST /login/v2`, `POST /login/v2/poll`, `GET /login/v2/flow[/{token}]`, `POST /login/v2/apptoken`.
- Password reset: `GET /lostpassword/reset/form/{token}/{userId}`, `POST /lostpassword/email`, `POST /lostpassword/set/{token}/{userId}` (BruteForce + AnonRateLimit).
- Remote wipe: `POST /core/wipe/check` and `/core/wipe/success` (AnonRateLimit).
- `GET /csrftoken`.
- Avatars: `GET /avatar/{userId}/{size}[/dark]`, `/avatar/guest/{guestName}/{size}[/dark]`.
- Static and misc: `GET /core/mimeicon`, `/core/js/oc.js`, `/js/{appName}/{fileName}`, `/css/{appName}/{fileName}`, `/unsupported`, `/error/403|404|418`, `/204`, `/ocm-provider/` (OCM discovery), `/.well-known/{service}`, `/core/references/preview/{referenceId}`.
- `GET /metrics`: answers 403 unless the client IP is in `openmetrics_allowed_clients` (default `['127.0.0.0/16','::1/128']`, `OpenMetricsController::isRemoteAddressAllowed`).

Core OCS routes (`/ocs/v2.php/…`):
- `GET /config`, `GET /cloud/capabilities`.
- `POST /person/check`: checks a `login`/`password` pair against `IUserManager::checkPassword` and answers 100 or 102; failures are throttled (`OCSController::personCheck`).
- `GET /identityproof/key/{cloudId}`: a user's public key.
- `GET /core/update` (`UpdateController::update`): runs the DB upgrade when `Util::needUpgrade()`. Refused if `upgrade.disable-web` (default false). `EventSource` applies `passesStrictCookieCheck` and `passesCSRFCheck`.
- References: `POST /references/extractPublic`, `GET|POST /references/resolvePublic` (AnonRateLimit). The fallback `LinkReferenceProvider` fetches the given URL and its OpenGraph image through `IClientService`.
- `GET /textprocessing/tasktypes`, `GET /translation/languages`, `POST /translation/translate` (Anon/UserRateLimit).

App routes:
- files_sharing:
  - `GET /index.php/s/{token}[/{fileid}]`, `GET|POST /index.php/s/{token}/authenticate/{redirect}`, `GET /index.php/s/{token}/download/{filename}`, `GET /index.php/s/{token}/preview`.
  - `GET /index.php/apps/files_sharing/publicpreview/{token}`.
  - `POST /index.php/apps/files_sharing/shareinfo` (BruteForce).
- cloud_federation_api: `POST /index.php/ocm/shares`, `POST /index.php/ocm/notifications`, `GET|POST|PUT|DELETE /index.php/ocm/{ocmPath}`, `GET /index.php/apps/cloud_federation_api/api/v1/jwks`, `POST …/api/v1/access-token`.
- federatedfilesharing: `POST /index.php/apps/federatedfilesharing/createFederatedShare`; OCS `POST /ocs/v2.php/cloud/shares` and `/cloud/shares/{id}/(reshare|permissions|accept|decline|unshare|revoke|move)`. Shared-secret `token` param, checked in handlers (`RequestHandlerController`).
- federation: OCS `GET|POST /ocs/v2.php/cloud/shared-secret` and legacy `/ocs/v2.php/apps/federation/api/v1/(shared-secret|request-shared-secret)` (BruteForce).
- oauth2: `GET /index.php/apps/oauth2/authorize`, `POST …/api/v1/token`, `POST …/api/v1/pushtoken` (BruteForce).
- dav: `GET /index.php/apps/dav/invitation/(accept|decline)/{token}`, `GET|POST …/invitation/moreOptions/{token}`.
- theming: `GET /index.php/apps/theming/(theme/{id}.css|image/{key}|manifest/{app}|favicon/{app}|icon/{app}|img/{app}/{image})`.
- profile: `GET /index.php/u/{targetUserId}`.
- files: `GET /index.php/apps/files/directEditing/{token}`, `…/preview-service-worker.js`.
- comments: `GET /index.php/apps/comments/notifications/view/{id}`.
- sharing (only when `sharing.unified_api_enable`): `GET /ocs/v2.php/apps/sharing/api/v1/secret`; `POST …/api/v1/share/{id}` with an optional `secret` (AnonRateLimit 1/5s, BruteForce `getShare`).
- user_ldap (only when enabled): `POST /index.php/apps/user_ldap/renewpassword`, `GET …/renewpassword/{user}`, `…/renewpassword/cancel`, `…/renewpassword/invalidlogin/{user}`.
- testing (not shipped): `RateLimitTestController` routes and `apps/testing/ajax/endpoint.php`.

Credentials an anonymous client can present, tried in this order by `OC::handleLogin`:
- Apache auth (`OC_User::handleApacheAuth`);
- AppAPI header;
- `Session::tryTokenLogin`: `Authorization: Bearer` app token, or the session cookie;
- remember-me cookies `nc_username`/`nc_token`/`nc_session_id` (`Session::loginWithCookie`);
- HTTP Basic (`Session::tryBasicAuthLogin`): wrong credentials raise `LoginException`.

Login attempts are throttled per IP under action `login` (`Session::logClientIn`).

### Share-link and token holder

Holds a share token, optionally with the share password.

- Token resolution, `lib/private/Share20/Manager.php` `getShareByToken`:
  - refuses empty tokens and tokens equal to an existing user id;
  - tries, in order: link shares (only if `core.shareapi_allow_links` = `yes`), remote shares by token, remote shares by OCM access token (via `PublicKeyTokenProvider`), then email, circle and room providers;
  - then `checkShare`: expired shares are deleted, shares of disabled accounts are hidden, and for link and email shares the owner must still be allowed to share;
  - folder link and email shares lose CREATE|UPDATE when `core.shareapi_allow_public_upload` ≠ `yes` (default `yes`).
- `Manager::checkPassword` rejects expired share passwords and verifies the hash with `IHasher`.
- AppFramework: `PublicShareMiddleware` covers controllers extending `OCP\AppFramework\PublicShareController` (`ShareController`, `PublicPreviewController`). It checks, in order:
  - throttling per `<Controller>::<method>`;
  - link sharing enabled: appconfig `core.shareapi_enabled` and `core.shareapi_allow_links`, both default true;
  - `isValidToken`;
  - `isAuthenticated`: password-protected shares need the token and password hash stored in the session (`validateTokenSession`).
- `AuthPublicShareController::authenticate` (POST, CSRF required) checks the password, regenerates the session id and stores the session.
- Handlers enforce share permissions themselves: `ShareController::downloadShare` checks `PERMISSION_READ` and `getHideDownload()`; `PublicPreviewController` checks `PERMISSION_READ`.
- Public DAV (`publicremote.php`, `publicwebdav.php`):
  - auth by `OCA\DAV\Connector\Sabre\PublicAuth`: token from path segment 3; Basic password checked by `shareManager->checkPassword` for link, email and circle shares; throttle action `public_dav_auth`; strict-cookie check when cookies are sent to a password share.
  - When outgoing server-to-server sharing is disabled, requests need `X-Requested-With: XMLHttpRequest`: all methods in v1, non-GET methods in v2.
  - Storage is wrapped in `PermissionsMask`/`DirPermissionsMask` from the share permissions. In v2, upload paths (`/uploads/`) add READ|DELETE to the mask. `FilesDropPlugin` is enabled when the share lacks READ.
- `BearerAuth` on `public.php` also accepts OCM access tokens: JWT `typ at+jwt` verified against the local JWKS, mapped to a remote share (`BearerAuth::resolveOcmSharedSecret`).
- Other token-in-URL surfaces: DAV invitation responses, password-reset tokens, login-flow-v2 tokens, direct-download tokens, direct-editing tokens, published-calendar tokens, mail verification (`/index.php/apps/provisioning_api/mailVerification/{key}/{token}/{userId}`; needs login).

### Federated peer server

Another Nextcloud/OCM server, or anyone claiming to be one.

- `cloud_federation_api` `RequestHandlerController::addShare` / `receiveNotification` (`#[FederationRateLimit]` on addShare) verify HTTP signatures via `OCMDiscoveryService::getIncomingSignedRequest`. Unsigned requests are accepted unless appconfig `core.ocm_signed_request_enforced` is true (default false). All checks are skipped when `core.ocm_signed_request_disabled` is true.
- federatedfilesharing OCS endpoints authenticate with the share's shared secret (`token`).
- `apps/federation`: trusted servers exchange a shared secret (`OCSAuthAPIController`). `FedAuth` (DAV Basic against `DbHandler::auth`) maps them to `principals/system/<server>`.
- `FederatedCalendarAuth` (added when appconfig `dav.enableCalendarFederation`, default true) authenticates `remote-calendars/…` with Basic credentials matched against `SharingMapper::getSharedCalendarsForRemoteUser`.
- Outbound, this server fetches peer discovery documents (`OCMDiscoveryService`, `OCMSignatoryManager`) and remote shares (`apps/files_sharing/lib/External/*`) through `IClientService`.

### Authenticated user (any account)

Main groups of the about 270 `#[NoAdminRequired]` methods, by registration:
- core (attributes in `core/Controller/*.php`):
  - OCS app passwords: `/ocs/v2.php/core/getapppassword` (password confirmation), `/core/apppassword`, `/core/apppassword/rotate`, `/core/apppassword/confirm`, `/core/getapppassword-onetime`;
  - unified search, autocomplete, contacts menu, hovercard, collaboration resources, task, text and image processing, teams, profile API;
  - references `/ocs/v2.php/references/resolve` (fetches URLs);
  - avatar upload, previews by file id;
  - login flow grant pages (`/index.php/login/flow/grant`, `/login/v2/grant`), 2FA challenge, `/index.php/logout`, `POST /index.php/login/confirm`.
- DAV (`remote.php/dav`, `RootCollection`): `files/<user>`, `calendars`, `addressbooks`, `principals`, `comments`, `systemtags*`, `uploads` (chunking v1/v2), `avatars`, `provisioning`; legacy `remote.php/webdav`, `/caldav`, `/carddav`.
- dav OCS: `/ocs/v2.php/apps/dav/api/v1/direct` (mints direct-download tokens), `…/outOfOffice/{userId}[/now]`, `…/federated_calendars/pending…`, `…/events/upcoming`.
- files_sharing OCS (`apps/files_sharing/appinfo/routes.php`): `/ocs/v2.php/apps/files_sharing/api/v1/shares[/{id}|/inherited|/pending…|/{id}/send-email]`, `deletedshares`, `sharees`, `sharees_recommended`, `remote_shares…`; web `…/settings/shareFolder`, `…/accept/{shareId}`, `externalShares` resource.
- files: `/index.php/apps/files/api/v1/(thumbnail/{x}/{y}/{file}|files/{path}|recent|stats|views|config|…)`, `/index.php/f/{fileid}`; OCS direct editing, templates, `transferownership`, `openlocaleditor`.
- provisioning_api (`/ocs/v2.php/cloud/…`):
  - self-service with `NoSubAdminRequired`: `GET /cloud/user`, `GET /cloud/users/{userId}`, `/cloud/user/fields`, phone search, `GET /cloud/groups/{groupId}/users`;
  - preferences: `/ocs/v2.php/apps/provisioning_api/api/v1/config/users/{appId}[/{key}]`;
  - app config: `POST …/api/v1/config/apps/{app}/{key}` needs password confirmation. The handler checks `AppConfigController::isAllowedToChangedKey` and `verifyConfigKey`, which refuses `installed_version`, `enabled`, `types` and core keys `public_*` / `remote_*`.
- settings (`NoSubAdminRequired` methods): personal auth tokens `/index.php/settings/personal/authtokens…` (create, wipe), personal info, WebAuthn registration, change password.
- user_status, dashboard, weather_status, files_reminders, files_versions / files_trashbin previews, systemtags, theming user backgrounds and themes, twofactor_backupcodes `/settings/create`, encryption user recovery (when enabled), files_external `userstorages` and `/api/v1/mounts`.
- workflowengine user flows: `/ocs/v2.php/apps/workflowengine/api/v1/workflows/user[/{id}]` (`UserWorkflowsController`), allowed unless appconfig `workflowengine.user_scope_disabled` (default false, `Manager::isUserScopeEnabled`).
- files_external user mounts need appconfig `files_external.allow_user_mounting` (default false, `apps/files_external/lib/ConfigLexicon.php`).
- DAV plugins on `remote.php/dav` that act on user requests (`apps/dav/lib/Server.php`): `ZipFolderPlugin` (folder downloads), `SearchPlugin` (DASL), `FilesReportPlugin`, `SharesPlugin`, `CommentsPlugin`, `SystemTagPlugin`, `ChunkingV2Plugin`, `LockPlugin`, and `ViewOnlyPlugin` for view-only shares (body not read).

Authorization between users sits in the handlers and in the VFS: per-user mounts (`lib/private/Files/SetupManager.php`), `View` path checks (`Filesystem::isValidPath` rejects `/../`), share storage, `DavAclPlugin`, `ISubAdmin::isUserAccessible` in provisioning handlers. Individual handlers beyond those named were not read: out of view.

### Subadmin and delegated admin

- Subadmin: provisioning_api users and groups methods without `NoSubAdminRequired` (`ProvisioningApiMiddleware`): `/ocs/v2.php/cloud/users` (list, add, edit, enable, disable, delete, wipe, group membership, welcome), `/cloud/groups` reads. Also settings `UsersController`. Per-target scoping in `UsersController` via `isSubAdminOfGroup` / `isUserAccessible` (`apps/provisioning_api/lib/Controller/UsersController.php`).
- Delegated admin: 46 `#[AuthorizedAdminSetting]` methods (settings, provisioning_api groups add/update/delete, theming, files_external global storages, user_ldap, federation, webhook_listeners, dav).
- Climbing from either to full admin crosses the boundary in `SecurityMiddleware`.

### Admin and operator (most trusted)

What the code lets an admin do:
- install and update apps from the app store (`lib/private/Installer.php`: certificate must chain to `resources/codesigning/root.crt`, not be revoked in `root.crl`, match the app id, and sign the archive);
- enable and disable apps (`/ocs/v2.php/cloud/apps/{app}`);
- create `Local` external storages over the server filesystem (`files_external_allow_create_new_local`, default true in `StoragesController::createStorage`);
- configure LDAP, mail (`/index.php/settings/admin/mailsettings`), webhooks (`apps/webhook_listeners` via `IClientService`) and workflows;
- run `occ`.

`occ` run as root switches to the owner of `config.php`; its comment says this "is not a true sandbox".

### Malicious content and remote responses

- Uploaded files reach preview providers. Default list in `PreviewManager::getEnabledDefaultProvider`: MarkDown, TXT, OpenDocument, PNG, JPEG, GIF, BMP, XBitmap, Krita, WebP, CDR, AVIF, unless `enabledPreviewProviders` is set; `enable_previews` default true.
- iCalendar and vCard bodies are parsed by Sabre in DAV (`CalDavValidatePlugin`, `CardDavValidatePlugin`); calendar invitations go through `IMipPlugin`.
- Filenames are checked by `FilenameValidator` (defaults: forbidden name `.htaccess`, extension `.filepart`, always `.part`).
- XML: DAV bodies, app `info.xml` (`InfoParser`, `simplexml_load_string`), OpenGraph/XSLT check in `LinkReferenceProvider`. External entities are disabled globally (`OC::boot`).
- Remote HTTP responses: webcal subscriptions (`apps/dav/lib/CalDAV/WebcalCaching/Connection.php`), link previews, app store (`lib/private/App/AppStore/Fetcher`), lookup server, OCM discovery.

### Cross-site attacker (victim's browser)

- `Request::passesCSRFCheck` requires the strict SameSite cookie and a valid `requesttoken` (GET, POST or `requesttoken` header). It returns true for any request carrying an `OCS-APIRequest` header.
- `SecurityMiddleware` fails a CSRF check only for non-OCS controllers, or for OCS requests without `OCS-APIREQUEST: true` and without a `Bearer` Authorization.
- SameSite cookies: `SameSiteCookieMiddleware` requires the lax cookie on `index.php` routes unless `#[NoSameSiteCookieRequired]`. `OC::performSameSiteCookieProtection` requires the strict cookie on other scripts, except `cron.php`, `public.php` and user agents matching `csrf.optout` (fallback `/^WebDAVFS/`, `/^Microsoft-WebDAV-MiniRedir/`).
- DAV `Auth::requiresCSRFCheck`:
  - exempt: GET, HEAD, OPTIONS; official desktop and mobile client user agents; logged-out requests; sessions that authenticated via DAV (except POST).
  - a failed POST logs the session out.
- CSP:
  - AppFramework responses get `ContentSecurityPolicy` merged with the default (`CSPMiddleware`): no inline script, nonce when CSPv3, inline style allowed.
  - legacy pages get `OC::addSecurityHeaders` (`script-src 'self' 'nonce-…'`, `frame-src *`, `connect-src *`, `img-src * data: blob:`).
  - `remote.php` and `public.php` send `default-src 'none'`.
- No method in apps/ or core/ carries `#[CORS]`.

### Local OS user and CI contributor

- `config.php` is written with mode `configfilemode`, default `0640` (`lib/private/Config.php`).
- The data directory defaults to `SERVERROOT/data` (`lib/private/Setup.php`), inside the web root. `Setup::protectDataDirectory` writes an Apache `.htaccess` denying access; other web servers are out of view.
- CI: `command-compile.yml` (issue_comment) refuses forks and requires write permission (`check-actor-permission`) before using `COMMAND_BOT_PAT`. `command-pull-3rdparty.yml` refuses forks; an actor-permission step was not seen in the lines read (not verified). `dependabot-approve-merge.yml` (pull_request_target) runs only for `dependabot[bot]`.

## assets

Assets:
- User file contents and metadata: data directory or object store, file cache tables, versions, trashbin.
- Calendars, contacts, comments, tags, account properties and their visibility scopes, user status.
- Credentials:
  - user passwords: hashed by `lib/private/Security/Hasher.php` (argon2id when PHP defines it, else argon2i, else bcrypt; `hashing_default_password` switches to `PASSWORD_DEFAULT`).
  - app passwords and session tokens (`lib/private/Authentication/Token/PublicKeyTokenProvider.php`): stored as `sha512(token . secret)`; the login password is RSA-OAEP-encrypted with a per-token key whose private key is encrypted with `ICrypto` under `token . secret`.
  - remember-me tokens: user preference `login_token`.
  - OAuth2: client secret compared as `ICrypto::calculateHMAC`; refreshed tokens encrypted with the new code (`OauthApiController::getToken`).
  - external-storage credentials: `ICrypto` in `apps/files_external/lib/Service/DBConfigService.php` and `lib/private/Security/CredentialsManager.php`.
  - share passwords, hashed (`Share20\Manager::checkPassword` requires `isPasswordHashed`).
  - server-side encryption keys (encryption app, not default-enabled).
  - OCM signatory and identity-proof private keys.
  - federation shared secrets.
- Instance secrets in `config/config.php` / `NC_*` env: `secret` (key for `ICrypto`, token hashing and HMACs), `passwordsalt`, `instanceid` (session cookie name), database, SMTP and object-store credentials.
- Capabilities equal to code execution or server file access: app install, `Local` external storage, `occ`, upgrade (`/ocs/v2.php/core/update`).
- Integrity of shipped code: core and app signatures (`lib/private/IntegrityCheck/Checker.php`, `integrity.check.disabled` default false), app-store certificate chain (`Installer::downloadApp`), committed `dist/` bundles, `3rdparty` submodule.
- Availability: unauthenticated heavy work (previews, translation, reference fetch, web cron, DAV), bounded by the throttler and rate limits.

Trust boundaries and where they are enforced:
1. Internet → PHP:
   - Host header against `trusted_domains` (`OC::initForRequest`, `TrustedDomainHelper`).
   - Client IP from `X-Forwarded-For` only when `REMOTE_ADDR` is in `trusted_proxies` (`Request::getRemoteAddress`, default header `HTTP_X_FORWARDED_FOR`). Protocol and host come from `overwrite*` config or, from trusted proxies, `X-Forwarded-Proto/Host` (`Request::getServerProtocol`, `getInsecureServerHost`).
2. Anonymous → user:
   - `SecurityMiddleware` (AppFramework default above).
   - DAV auth plugin backends (`apps/dav/lib/Server.php`): `PublicAuth`, then app-added backends (`SabrePluginAuthInitEvent`: `FedAuth`, `FederatedCalendarAuth`), then `BearerAuth`, then `Connector\Sabre\Auth` (session or Basic via `logClientIn`; 2FA must be complete, `needsSecondFactor`).
   - Token rules in `lib/private/User/Session.php`:
     - session (temporary) tokens are refused from a Bearer header and as Basic passwords;
     - one-time tokens are valid only for `/core/getapppassword-onetime`;
     - `logClientIn` (Basic auth for DAV, OCS and index.php) refuses plain passwords when `token_auth_enforced` (default false) or the user has 2FA (`PasswordLoginForbiddenException`);
     - `TwoFactorAuth\Manager::needsSecondFactor` returns false for sessions holding `app_password` or `app_api`;
     - token credentials are rechecked every 5 minutes (`checkTokenCredentials`);
     - scoped tokens without filesystem access get no mounts (`LockdownManager::canAccessFilesystem` in `SetupManager`).
3. User → user / share recipient → owner: per-user VFS mounts and jails, share storage wrappers and permission masks (above), DAV ACL, handler checks.
4. User → subadmin → admin:
   - `SecurityMiddleware`, `ProvisioningApiMiddleware`, `SubadminMiddleware`, `AuthorizedGroupMapper`.
   - `allowed_admin_ranges` (`lib/private/Security/Ip/RemoteAddress.php`: empty or invalid means unrestricted).
   - `#[PasswordConfirmationRequired]` (`PasswordConfirmationMiddleware`): last confirmation within 30 min + 15 s, or strict mode re-checking the Basic password. Skipped when the token scope sets skip-password-validation, when the user backend cannot confirm passwords, for backends `user_saml`/`user_globalsiteselector`, and, with no session token, for IPs in `allowed_no_password_confirmation_ranges`.
5. Server → network: `lib/private/Http/Client/Client.php` `preventLocalAddress` on every verb and on redirects, `RemoteHostValidator` (local hostnames and IP ranges via `HostnameClassifier` / `IpAddressClassifier`), `DnsPinMiddleware`.
   - Off when `allow_local_remote_servers` is true (code default false; the sample file shows `true` as an example).
   - Per-call bypass `['nextcloud']['allow_local_address' => true]` in: `WebcalCaching/Connection.php` (appconfig `dav.webcalAllowLocalAccess` = `yes`, default `no`), `lib/private/Preview/Imaginary.php`, `lib/public/SetupCheck/CheckServerResponseTrait.php`.
   - files_external SMB, SFTP, FTP, S3 and Swift backends (`apps/files_external/lib/Lib/Storage`) do not reference `IRemoteHostValidator`.
6. Instance ↔ federated peers: HTTP signatures (`lib/private/Security/Signature`, `lib/private/OCM`; enforcement default off), shared secrets, trusted-server list (`apps/federation`).
7. Abuse limits:
   - `lib/private/Security/Bruteforce/Throttler.php`: `auth.bruteforce.protection.enabled` default true, `auth.bruteforce.max-attempts` default 10 (`IThrottler::MAX_ATTEMPTS`), max delay 25 s; allow-list appconfig `bruteForce.whitelist_*` (`BruteforceAllowList`).
   - Applied by `BruteForceMiddleware` for `#[BruteForceProtection]` and `$response->throttle()`.
   - `RateLimitingMiddleware` for `#[AnonRateLimit]` / `#[UserRateLimit]` (`ratelimit.protection.enabled` default true).
8. Browser: CSRF, SameSite and CSP as listed under the cross-site attacker; template escaping (facts).

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


- `SECURITY.md` points to "our threat model and accepted risks" at https://nextcloud.com/security/threat-model "to learn what is currently considered a security vulnerability versus expected behavior", and to HackerOne for "in scope or bounty eligible". That document is not in the repo: out of view, so it narrows nothing here. It also says only major versions within "1 year after their initial release" get security updates, and that for apps "not maintained by Nextcloud" the team "will try to coordinate with the current maintainer".
- `AGENTS.md` "Scope of this repository": "the Nextcloud server core and the bundled apps: files, encryption, external storage, sharing, deleted files, versions, LDAP, and WebDAV Auth. Issues and changes for other components belong in their respective repositories". The repo nevertheless contains and ships dav, oauth2, federation, theming, provisioning_api and the other apps under `apps/`.
- `README.md`: several default release apps (e.g. First run wizard, Activity) "are missing in `master`"; git checkouts on `stable*` branches "should never be used on production systems".
- `Caddyfile`: "THIS IS AN EXPERIMENTAL FEATURE / DO NOT USE THIS IN PRODUCTION"; excluded from releases (`.nextcloudignore`).
- `.devcontainer/README.md`: the dev container installs with fixed credentials (admin/admin, postgres/postgres). Dev only, excluded from releases.
- `occ` comment: switching from root to the config owner "drops primary root privileges but is not a true sandbox … Does not clear environment variables nor supplementary groups".
- Requirements `config/config.sample.php` places on deployers:
  - `trusted_domains`: "Do not remove this, as it performs necessary security checks".
  - `debug`: "Only use for local development, not in production".
  - disabling brute-force or rate-limit protection "is discouraged for security reasons"; brute-force testing mode only "for debugging and on CI".
  - `forwarded_for_headers`: "Incorrect configuration allows clients to spoof their IP address".
  - `check_for_working_htaccess`: "a crucial security check on Apache servers that should always be set to true".
  - `openmetrics_allowed_clients`: "Keep this list as restrictive as possible".
  - `csrf.optout`: "Use only if you understand the implications".

## production

Repository github.com/cx-benchmark/server, read at the commit filed. Classification follows `.nextcloudignore` (release exclusions), `.htaccess` (web-denied paths) and what the entry scripts load.
- `index.php`, `remote.php`, `public.php`, `status.php`, `cron.php`, `console.php`, `occ`, `version.php`, `index.html`, `robots.txt`, `.htaccess`, `.user.ini`: production (served or executed; not excluded).
- `lib/`: production (core PHP; `lib/composer` autoloader, `lib/l10n` translations).
- `core/`: production (controllers, templates, `core/src` frontend sources compiled into `dist/`, skeleton files, `shipped.json`). `core/openapi*.json` is generated API documentation.
- `apps/`: production, bundled apps, except `apps/testing` (removed by `.nextcloudignore`: test-only) and `apps/*/tests` (removed by the global `tests` rule).
- `dist/`: production, compiled JS/CSS served to browsers (marked `binary` in `.gitattributes`).
- `ocs/`, `ocs-provider/`: production entry scripts.
- `resources/`: production data (`codesigning/root.crt`, `root.crl`, `core.crt`, `config/ca-bundle.crt`, mimetype maps); `resources/update-locales.php` and `config/mimetypenames-update.sh` are tooling.
- `3rdparty/`: production, vendored PHP dependencies (submodule); not checked out here, out of view.
- `config/`: `CAN_INSTALL` is shipped and gates the web installer; `config.sample.php` is shipped documentation; `config.php` is excluded.
- `themes/`: shipped example theme (`themes/example`), not active unless configured.
- `tests/`: tests (PHPUnit, Behat, Playwright, docker configs); excluded.
- `build/`: build and CI tooling (`demi.sh`, psalm and rector configs, frontend build workspaces, integration tests); excluded and web-denied.
- `vendor-bin/`: dev tool composer roots (phpunit, psalm, behat, cs-fixer, rector, openapi-extractor); excluded.
- `.github/`: CI workflows and repo config; excluded.
- `.devcontainer/`, `.idea/`, `.tx/`, `contribute/`: developer tooling and docs; excluded.
- `Caddyfile`: experimental server config; excluded.
- `__mocks__`, `__tests__` (symlinks into `build/frontend`), `autotest*.sh`, `package.json`, `package-lock.json`, `composer.json`, `composer.lock`, `psalm*.xml`, `vite/vitest/eslint/stylelint/playwright` configs, `flake.nix`, `Makefile`, `openapi.json`: build and test tooling (most listed in `.nextcloudignore`).
- `AGENTS.md`, `CLAUDE.md`, `README.md`, `SECURITY.md`, `DESIGN.md`, `CHANGELOG.md`, `AUTHORS`, `COPYING*`, `LICENSES/`, `REUSE.toml`: documentation and licensing.

## facts

Repository github.com/cx-benchmark/server:
- Security policy: `SECURITY.md` exists (HackerOne reporting; points to an external threat model).
- Templates:
  - server-side PHP templates (`lib/private/Template/functions.php`): `p()` escapes with `htmlspecialchars(…, ENT_QUOTES, 'UTF-8')` (`OCP\Util::sanitizeHTML`); `print_unescaped()` prints raw. About 65 `print_unescaped` call sites in `core/templates` and `apps/*/templates`.
  - frontend: Vue SFCs in `apps/*/src` and `core/src`; Vue interpolation escapes, and `v-html` appears in about 40 places. `dompurify` is a dependency (`package.json`).
- Serialization:
  - JSON request bodies decoded with `json_decode(…, JSON_THROW_ON_ERROR)`; form bodies for non-GET/POST via `parse_str` (`Request::decodeContent`).
  - XML through Sabre and SimpleXML, with external entities disabled globally (`OC::boot`).
  - PHP `unserialize` in production code, each with `allowed_classes` restricted: `PublicKeyTokenProvider` (cache), `apps/dav/lib/DAV/CustomPropertiesBackend.php` (DB property values), `lib/private/Command/QueueBus.php`, `CommandJob.php`, `TaskProcessing/Manager.php`, `Profiler/FileProfilerStorage.php`, `OpenMetrics/Exporters/Cached.php`. `RemoveBrokenProperties` uses `allowed_classes => false`. One unrestricted call is in migration `apps/user_ldap/lib/Migration/Version1190Date20230706134108.php` (DB column `owncloudusers`).
  - JWT via firebase/php-jwt (`BearerAuth`, `TokenController`).
- Authentication and sessions:
  - PHP session named by instance id, data encrypted (`CryptoWrapper`, cookie `oc_sessionPassphrase`, SameSite Lax, httponly).
  - `session_lifetime` default 86400 (`OC::getSessionLifeTime`).
  - remember-me cookies, `remember_login_cookie_lifetime` default 15 days (`Session::setMagicInCookie`).
  - CSRF token `requesttoken` (`CsrfTokenManager`).
  - SameSite marker cookies `nc_sameSiteCookielax` and `nc_sameSiteCookiestrict`, `__Host-` prefixed when secure with path `/`.
  - app passwords and Bearer tokens (`PublicKeyTokenProvider`); OAuth2 (`apps/oauth2`); login flow v1/v2 (`core/Controller/ClientFlowLogin*`).
  - WebAuthn (`auth.webauthn.enabled` default true); TOTP and other 2FA providers through `lib/private/Authentication/TwoFactorAuth` (backup codes app in repo).
  - LDAP backend (`apps/user_ldap`), Apache auth (`OC_User::handleApacheAuth`), AppAPI header.
  - The session id is regenerated in `Session::login`, in `Session::completeLogin` (default `$regenerateSessionId = true`), in `loginWithCookie`, and on share-password success (`AuthPublicShareController::authenticate`).
  - Absolute URLs (mails, redirects) come from `URLGenerator::getBaseUrl`, which uses `Request::getServerProtocol` and `getServerHost`: `overwritehost`, else the Host header if trusted, else the first `trusted_domains` entry. The CLI uses `overwrite.cli.url`.
- Defaults that change exposure (code defaults):
  - `debug` false: in debug, the strict-cookie failure is not fatal outside index.php (`OC::performSameSiteCookieProtection`), `PrincipalCollection` listing is enabled in `caldav.php`, and the Sabre browser plugin is enabled (`apps/dav/lib/Server.php`).
  - `allow_local_remote_servers` false.
  - `auth.bruteforce.protection.enabled` true; `ratelimit.protection.enabled` true.
  - `token_auth_enforced` false.
  - `appstoreenabled` true (`Installer.php`, `Fetcher.php`).
  - `files_external_allow_create_new_local` true.
  - `upgrade.disable-web` false.
  - `integrity.check.disabled` false.
  - `profile.enabled` true (`ProfileManager`).
  - `openmetrics_allowed_clients` loopback only.
  - `trusted_proxies` empty.
  - appconfig `core.backgroundjobs_mode` `ajax`.
  - appconfig `core.ocm_signed_request_enforced` false.
  - `core.shareapi_enabled`, `core.shareapi_allow_links` and `core.shareapi_allow_public_upload` yes.
  - `files_sharing.outgoing_server2server_share_enabled` and `incoming_server2server_share_enabled` true (`CalendarFederationConfig` reads them; federatedfilesharing reads its own; not verified).
  - `sharing.unified_api_enable` false.
  - `files_external.allow_user_mounting` false.
  - `dav.webcalAllowLocalAccess` `no`.
  - preview providers as listed under malicious content.
  - log file `<datadirectory>/nextcloud.log` (`lib/private/Log/Rotate.php`).
- Hardening at the PHP level (no compiled code):
  - `OC::setRequiredIniValues` sets `display_errors=0`.
  - `.htaccess` sends `X-Content-Type-Options nosniff`, `X-Frame-Options SAMEORIGIN`, `Referrer-Policy no-referrer` (`same-origin` on `/login`), `X-Robots-Tag`; `OC::addSecurityHeaders` sends them as a fallback when `modHeadersAvailable` is not set.
  - Strict types are declared in most files.
  - CI static analysis: psalm (`psalm.xml`, security baseline `build/psalm-baseline-security.xml`), CodeQL (`.github/workflows/codeql.yml`), rector, php-cs.
- Where routes, schemas and permissions are defined:
  - routes: `apps/*/appinfo/routes.php` (`routes`, `ocs`, `resources` keys), `#[FrontpageRoute]`/`#[ApiRoute]` attributes on controller methods (loaded by `Router::loadAttributeRoutes`), `core/routes.php`.
  - permissions: method attributes in `lib/public/AppFramework/Http/Attribute/`, enforced by the middleware above.
  - OpenAPI: `openapi.json`, `core/openapi*.json`, `apps/*/openapi*.json` (generated).
  - DB schemas: `core/Migrations` and `apps/*/lib/Migration`.
  - DAV tree: `apps/dav/lib/RootCollection.php`.
  - shipped and always-enabled apps: `core/shipped.json`.
- Languages, by lines in git-tracked files excluding tests, `build/`, `dist/` and l10n:
  - PHP about 537k lines (≈82%), Vue about 62k (≈9.5%), TypeScript about 44k (≈6.7%), JavaScript about 7k (≈1%), SCSS/CSS about 7k (≈1%), shell under 1k.
  - In addition: about 304k lines of PHP tests, about 247k lines of generated l10n JS, and compiled `dist/` bundles.


<!-- written at these commits:
6b6317280f8ed50277369c33cee070a643d29654 https://github.com/cx-benchmark/server
-->
