use crate::core::sign_in::with_default_scopes;
use std::error::Error;

pub struct LogtoConfig<'a> {
    pub endpoint: String,
    pub app_id: String,
    pub scopes: Option<Vec<&'a str>>,
    pub resources: Option<Vec<&'a str>>,
    pub prompt: Option<&'a str>,
}
struct AccessToken<'a> {
    token: &'a str,
    scope: &'a str,
    expires_at: u32,
}

impl<'a> LogtoConfig<'a> {
    /// Normalizes the Logto client configuration per the following rules:
    /// - Add default scopes (`openid`, `offline_access` and `profile`) if not provided.
    ///
    /// # Examples
    ///
    /// ```
    /// # use logto_rs::client::LogtoConfig;
    /// let mut logto_config: LogtoConfig = LogtoConfig {
    ///     endpoint: "https://logto.dev/api".to_string(),
    ///     app_id: "app_id_value".to_string(),
    ///     scopes: Some(vec!["email"]),
    ///     resources: Some(vec!["resource 1"]),
    ///     prompt: Some("prompt_value")
    /// };
    ///
    /// let logto_config = logto_config.normalize().unwrap();
    ///
    /// assert_eq!(logto_config.scopes, Some(vec!["email", "offline_access", "openid", "profile"]))
    ///
    /// ```
    pub fn normalize(&mut self) -> Result<Self, Box<dyn Error>> {
        Ok(LogtoConfig {
            endpoint: self.endpoint.clone(),
            app_id: self.app_id.clone(),
            scopes: Some(with_default_scopes(self.scopes.clone())),
            resources: self.resources.clone(),
            prompt: self.prompt.clone(),
        })
    }
}

struct LogtoClient<'a> {
    logto_config: LogtoConfig<'a>,
    access_token: AccessToken<'a>,
}
