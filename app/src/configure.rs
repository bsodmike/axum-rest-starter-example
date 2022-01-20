use app_core::error::{self, Error, Kind};
use std::collections::HashMap;

pub struct ConfigInfo<V> {
    flag: V,
}

pub trait FetchFromConfig<T>: private::Sealed {
    fn fetch_config(&self, config: &HashMap<String, String>) -> T;
}

impl<V> FetchFromConfig<bool> for ConfigInfo<V>
where
    V: std::fmt::Debug + std::fmt::Display,
{
    fn fetch_config(&self, config: &HashMap<String, String>) -> bool {
        let value = match config.get(&self.flag.to_string()) {
            Some(value) => value.to_string(),
            None => String::new(),
        };

        if value.eq("true") || value.eq("false") {
            match value.parse::<bool>() {
                Ok(value) => value,
                Err(error) => panic!(
                    "Unknown error parsing configuration flag {}. Err: {:#?}",
                    &self.flag, error
                ),
            }
        } else {
            false
        }
    }
}

impl<V> FetchFromConfig<String> for ConfigInfo<V>
where
    V: std::fmt::Debug + std::fmt::Display,
{
    fn fetch_config(&self, config: &HashMap<String, String>) -> String {
        match config.get(&self.flag.to_string()) {
            Some(value) => value.to_string(),
            None => String::new(),
        }
    }
}

// Prevent users from implementing the FetchFromConfig trait.
mod private {
    pub trait Sealed {}
    impl<V> Sealed for super::ConfigInfo<V> {}
}

pub fn fetch<T>(flag: &str) -> Result<T, Error>
where
    // Trait bound to implement FetchFromConfig<T> for ConfigInfo<String>,
    // to allow it to call `fetch_config` as defined by the trait, returning T.
    ConfigInfo<String>: FetchFromConfig<T>,
{
    let config = match crate::CONFIG.clone().try_into::<HashMap<String, String>>() {
        Ok(config) => config,
        Err(error) => panic!("Error: {:?}", error),
    };

    let cli_info = ConfigInfo {
        flag: String::from(flag),
    };
    Ok(cli_info.fetch_config(&config))
}

pub async fn fetch_configuration(key: &str) -> Result<String, error::Error> {
    let result: String = match fetch::<String>(key) {
        Ok(value) if value.is_empty() => {
            tracing::error!("Configuration string {:?} is blank!", key);

            let mut new_err = error::new(Kind::ConfigurationSecretEmpty);
            new_err.set_cause(format!("Configuration string {:?} is blank!", key).into());

            return Err(new_err);
        }
        Ok(value) => value,
        Err(err) => {
            tracing::error!("Configuration string {:?} is blank!", key);

            let mut new_err = error::new(Kind::ConfigurationSecretMissing);
            new_err.set_cause(Box::new(err));

            return Err(new_err);
        }
    };

    Ok(result)
}
