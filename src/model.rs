use crate::verdict::Classification;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelPass {
    Classifier,
    SevereHarmVerifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Clone, Debug)]
pub struct ModelResult {
    pub classification: Classification,
    pub usage: ModelUsage,
}
