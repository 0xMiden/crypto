(function() {
    const implementors = Object.fromEntries([["miden_crypto",[]],["miden_lifted_air",[]],["miden_lifted_stark",[]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":59,"fragment_lengths":[19,24,26]}