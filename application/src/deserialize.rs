use serde::{Deserialize, Deserializer, de::DeserializeOwned};

#[inline]
pub fn deserialize_optional<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;

    Ok(serde_json::from_value(value).ok())
}

#[inline]
pub fn deserialize_defaultable<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned + Default,
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;

    Ok(serde_json::from_value(value).unwrap_or_default())
}

#[inline]
pub fn deserialize_nullable<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned + Default,
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(T::default());
    }

    serde_json::from_value(value).map_err(serde::de::Error::custom)
}
