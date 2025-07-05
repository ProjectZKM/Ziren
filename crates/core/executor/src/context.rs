use core::mem::take;

use hashbrown::HashMap;

use crate::{
    hook::{hookify, BoxedHook, HookEnv, HookRegistry},
    subproof::SubproofVerifier,
};

/// Context to run a program inside Ziren.
#[derive(Clone, Default)]
pub struct ZKMContext<'a> {
    /// The registry of hooks invocable from inside Ziren.
    ///
    /// Note: `None` denotes the default list of hooks.
    pub hook_registry: Option<HookRegistry<'a>>,

    /// The verifier for verifying subproofs.
    pub subproof_verifier: Option<&'a dyn SubproofVerifier>,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,

    /// Skip deferred proof verification.
    pub skip_deferred_proof_verification: bool,
}

/// A builder for [`ZKMContext`].
#[derive(Clone, Default)]
pub struct ZKMContextBuilder<'a> {
    no_default_hooks: bool,
    hook_registry_entries: Vec<(u32, BoxedHook<'a>)>,
    subproof_verifier: Option<&'a dyn SubproofVerifier>,
    max_cycles: Option<u64>,
    skip_deferred_proof_verification: bool,
}

impl<'a> ZKMContext<'a> {
    /// Create a new context builder. See [`ZKMContextBuilder`] for more details.
    #[must_use]
    pub fn builder() -> ZKMContextBuilder<'a> {
        ZKMContextBuilder::new()
    }
}

impl<'a> ZKMContextBuilder<'a> {
    /// Create a new [`ZKMContextBuilder`].
    ///
    /// Prefer using [`ZKMContext::builder`].
    #[must_use]
    pub fn new() -> Self {
        ZKMContextBuilder::default()
    }

    /// Build and return the [`ZKMContext`].
    ///
    /// Clears and resets the builder, allowing it to be reused.
    pub fn build(&mut self) -> ZKMContext<'a> {
        // If hook_registry_entries is nonempty or no_default_hooks true,
        // indicating a non-default value of hook_registry.
        let hook_registry =
            (!self.hook_registry_entries.is_empty() || self.no_default_hooks).then(|| {
                let mut table = if take(&mut self.no_default_hooks) {
                    HashMap::default()
                } else {
                    HookRegistry::default().table
                };
                // Allows overwriting default hooks.
                table.extend(take(&mut self.hook_registry_entries));
                HookRegistry { table }
            });
        let subproof_verifier = take(&mut self.subproof_verifier);
        let cycle_limit = take(&mut self.max_cycles);
        let skip_deferred_proof_verification = take(&mut self.skip_deferred_proof_verification);
        ZKMContext {
            hook_registry,
            subproof_verifier,
            max_cycles: cycle_limit,
            skip_deferred_proof_verification,
        }
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within Ziren by writing to the specified file descriptor `fd`
    /// with [`zkm_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`zkm_zkvm::io::read`].
    pub fn hook(
        &mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> &mut Self {
        self.hook_registry_entries.push((fd, hookify(f)));
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(&mut self) -> &mut Self {
        self.no_default_hooks = true;
        self
    }

    /// Add a subproof verifier.
    ///
    /// The verifier is used to sanity check `verify_zkm_proof` during runtime.
    pub fn subproof_verifier(&mut self, subproof_verifier: &'a dyn SubproofVerifier) -> &mut Self {
        self.subproof_verifier = Some(subproof_verifier);
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    pub fn max_cycles(&mut self, max_cycles: u64) -> &mut Self {
        self.max_cycles = Some(max_cycles);
        self
    }

    /// Set the skip deferred proof verification flag.
    pub fn set_skip_deferred_proof_verification(&mut self, skip: bool) -> &mut Self {
        self.skip_deferred_proof_verification = skip;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{subproof::NoOpSubproofVerifier, ZKMContext};

    #[test]
    fn defaults() {
        let ZKMContext { hook_registry, subproof_verifier, max_cycles: cycle_limit, .. } =
            ZKMContext::builder().build();
        assert!(hook_registry.is_none());
        assert!(subproof_verifier.is_none());
        assert!(cycle_limit.is_none());
    }

    #[test]
    fn without_default_hooks() {
        let ZKMContext { hook_registry, .. } =
            ZKMContext::builder().without_default_hooks().build();
        assert!(hook_registry.unwrap().table.is_empty());
    }

    #[test]
    fn with_custom_hook() {
        let ZKMContext { hook_registry, .. } =
            ZKMContext::builder().hook(30, |_, _| vec![]).build();
        assert!(hook_registry.unwrap().table.contains_key(&30));
    }

    #[test]
    fn without_default_hooks_with_custom_hook() {
        let ZKMContext { hook_registry, .. } =
            ZKMContext::builder().without_default_hooks().hook(30, |_, _| vec![]).build();
        assert_eq!(&hook_registry.unwrap().table.into_keys().collect::<Vec<_>>(), &[30]);
    }

    #[test]
    fn subproof_verifier() {
        let verifier = NoOpSubproofVerifier;
        let ZKMContext { subproof_verifier, .. } =
            ZKMContext::builder().subproof_verifier(&verifier).build();
        assert!(subproof_verifier.is_some());
    }
}
