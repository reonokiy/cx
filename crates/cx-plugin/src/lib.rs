pub mod injector;
pub mod manifest;
pub mod policy;
pub mod registry;
pub mod validator;

pub use injector::{
    AuthInjector, InjectionContext, InjectionError, InjectionOutcome, ResolvedSecretMap,
    UpstreamHttpRequest,
};
pub use manifest::{InjectMode, InjectRuleConfig, ParamSpec, PolicyEffect, PolicyRuleConfig, ProviderManifest};
pub use policy::{CompiledPolicy, PolicyCompileError, PolicyDecision};
pub use registry::{
    GENERIC_HTTP_PROVIDER_ID, PlatformRoutingOverride, PlatformSpec, PluginError, ProfileSpec,
    ProviderCatalogEntry, ProviderParamInfo, ProviderRegistry, ResolvedPlatform, ResolvedProfile,
    SecretBinding, SecretScope, validate_identifier,
};
pub use validator::{HostPatternValidator, ValidationError};
