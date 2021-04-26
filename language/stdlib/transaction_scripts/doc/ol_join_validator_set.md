
<a name="join"></a>

# Script `join`





<pre><code><b>use</b> <a href="../../modules/doc/MinerState.md#0x1_MinerState">0x1::MinerState</a>;
<b>use</b> <a href="../../modules/doc/Signer.md#0x1_Signer">0x1::Signer</a>;
<b>use</b> <a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse">0x1::ValidatorUniverse</a>;
</code></pre>




<pre><code><b>public</b> <b>fun</b> <a href="ol_join_validator_set.md#join">join</a>(validator: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="ol_join_validator_set.md#join">join</a>(validator: &signer) {
    <b>let</b> addr = <a href="../../modules/doc/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(validator);
    // <b>if</b> is above threshold <b>continue</b>, or raise error.
    <b>assert</b>(<a href="../../modules/doc/MinerState.md#0x1_MinerState_node_above_thresh">MinerState::node_above_thresh</a>(validator, addr), 01);
    // <b>if</b> is not in universe, add back
    <b>if</b> (!<a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse_is_in_universe">ValidatorUniverse::is_in_universe</a>(addr)) {
        <a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse_add_self">ValidatorUniverse::add_self</a>(validator);
    };
    // Initiate jailbit <b>if</b> not present
    <b>if</b> (!<a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse_exists_jailedbit">ValidatorUniverse::exists_jailedbit</a>(addr)) {
        <a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse_unjail_self">ValidatorUniverse::unjail_self</a>(validator);
    };

    // <b>if</b> is jailed, try <b>to</b> unjail
    <b>if</b> (<a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse_is_jailed">ValidatorUniverse::is_jailed</a>(addr)) {
        <a href="../../modules/doc/ValidatorUniverse.md#0x1_ValidatorUniverse_unjail_self">ValidatorUniverse::unjail_self</a>(validator);
    };
}
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/libra/lip/blob/master/lips/lip-2.md
[ROLE]: https://github.com/libra/lip/blob/master/lips/lip-2.md#roles
[PERMISSION]: https://github.com/libra/lip/blob/master/lips/lip-2.md#permissions
