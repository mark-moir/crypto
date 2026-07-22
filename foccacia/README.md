
# ATTENTION: Work in progress towards potential future contribution.

Ths crate is experimental, not fully documented, has not been reviewed or audited, and is not ready for any kind of serious use.

# Composable Committed Components (CCC): A modular framework for composing Zero Knowledge Proof features

This crate provides a framework (CCC) that enables defining "components" that support Zero Knowledge
Proofs (ZKPs) over committed values and linking them together via "equalities": ZKPs that prove that
selected values committed in two components are equal (without disclosing the values).  This enables
building graph structures in which components are nodes and equalities are edges, thus combining
multiple independent components into useful ZKP systems in a modular way.

This modular approach enables composing components that use different underlying ZKP mechanisms (for
example operating on different elliptic curves), and replacing or adding new components
independently in order to include additional features and to improve performance and/or security
(for example to incrementally replace components with Post Quantum alternatives as they become
available).

Motivation for developing this framework includes enabling:
- implementing [our VCA
  abstraction](https://github.com/mark-moir/anoncreds-v2-rs/blob/vca-main/src/vca/README.md) over
  combinations of features from different "monolithic" proof systems, such as [AnonCreds
  2.0](https://github.com/anoncreds/anoncreds-v2-rs) (AC2C) and [DockNetwork
  crypto](https://github.com/docknetwork/crypto/tree/main/proof_system) (DNC)
- presentations of multiple credentials of different formats, linking them via common attributes without disclosing their values
-  "device binding" with verifiable credentials implemented over VCA

Note that CCC is a framework for combining and orchestrating ZKPs over committed values using
multiple components as well as ZKPs for required equalities between the committed values involved in
those proofs.  The framework itself does not specify or ensure properties of the ZKPs; it is up to
implementers to ensure that each component and equality provides the necessary properties.

## Introduction

This work is based on a generalisation of the vision described in "Vision: A Modular Framework for
Anonymous Credential Systems" by Anja Lehmann, Andrey Sidorenko, and Alexandros Zacharakis
([LSZ25](https://eprint.iacr.org/2025/1981)).

The vision espoused in LSZ25 focuses on combining:

  a) an Anonymous Credential system that supports proving and verifying knowledge of a signature
  over some attributes, while disclosing selected attributes and committing to others; and

  b) proving and verifying additional "plug and play" ZKP properties about values committed to in
  the Anonymous Credential system, for example that an attribute's signed value is within a
  specified range, without disclosing the value.

This enables a modular approach in which components can be improved or replaced independently of each
other, in contrast to more monolithic approaches.  Lehman et al. point out benefits including:

- avoiding duplication of effort to include (minor variations on) the same signature schemes in multiple projects;
- enabling improving the ZKP implementation of a "plug and play" feature independently of the signature scheme
used for the Anonymous Credential system; and
- enabling incremental progress towards quantum-safe systems by replacing one component at a time as quantum-safe
implementations become available and improve over time.

Our work builds on the vision of LSZ25 by providing a concrete implementation based on a
generalisation of the proposed framework, resulting in significant additional benefits.

## Generalising the framework of LSZ25

The LSZ25 framework comprises two relations: CD and R.  CD represents the Anonymous Credential
system, with commitments for selected attributes, and R represents an additional ZKP feature proving
an arbitrary property about the committed values.  It is not difficult to generalise the framework
to support multiple additional features via relations R_1, R_2, as envisaged by the prose in LSZ25,
but the formalism in LSZ25 does not explicitly do so.

In contrast, we define uniform "components" for arbitrary ZKP features, each of which might or might not be
instantiated to include an Anonymous Credential system, and link them together via
"equalities" that enable proving and verifying that the values on which commitments used by two
components are equal.  This more general approach has several significant advantages:

- it enables composition of as many ZKP features as desired, not just the two in the formalism of LSZ25;
- an "equality" proves that a committed value used by one component is equal to a committed value
  used by another, but does not require the commitments themselves to be equal; this is more
  flexible, more convenient, and amenable to finer-grained parallelism;
- because there is no "special" component (like CD in LSZ25), we can build a graph
  with no Anonymous Credential system or, importantly, with multiple.

The latter possibility is important because it enables combining multiple kinds of credential
systems, for example with different underlying signature schemes.  To our knowledge, all prior
"monolithic" anonymous credential systems that enable proving equality of attributes between
multiple presented credentials require that all credentials were signed with the same version of the
same underlying signature scheme.  This necessitates an assumption in a use case involving
multi-credential presentations that the Issuers of all presented credentials use the same signature
algorithm; this is particularly impractical given that different Issuers will evolve their systems over time
and are highly unlikely to all change at once.  Our approach eliminates these restrictions.

Furthermore, we plan to enable components that support proofs via our [VCA
abstraction](https://github.com/mark-moir/anoncreds-v2-rs/blob/vca-main/src/vca/README.md), which in
turn will enable use cases that support presentations that include credentials in multiple formats.
For example, a Holder could present two AnonCreds credentials (which must share a "link secret" due
to requirements in [the
spec](https://anoncreds.github.io/anoncreds-spec/#holder-create-and-store-link-secret)) along with an
SD-JWT credential that contains an attribute that is proved to be equal to an attribute in one of the
AnonCreds credentials (e.g., Social Security Number or even the same link secret as used for the
AnonCreds credentials).

## Device binding example

An important example that is highlighted in LSZ25 is "device binding", whereby an Issuer issues a
credential that can be presented only using the device (e.g., smart phone) for which it was issued.
This requires the Issuer to embed the device's public key in the credential, and for the Holder to
provide a proof that it has signed a challenge message using the secure element on that device,
which the Verifier can verify without learning the public key (this is critical for privacy; otherwise
all Verifiers can correlate every presentation made using credentials from that device).

We have constructed a component for proving knowledge of such a signature, and another component for
enabling selective disclosure with a BBS+ signature via the DNC proof system (BBS_SD_DNCPS). An equality
enables proving that the public key (split into two attributes) signed into that BBS+ signature
represents the same public key against which the challenge signature verifies.  This is challenging,
particularly because the ECDSA signatures
generated by smart phones operate over a different elliptic curve than BBS+ signatures do.  The
[equality_across_groups](../equality_across_groups) crate enabled us to build an equality edge
that bridges this gap.

## CCC Layout

The structure of the `composable_committed_components` crate is summarised as follows:

  - `src/api.rs` public traits (`CCCGraphApi`, `CCCGraphMaker`) and types for graph users and builders
  - `src/interfaces/` shared abstractions:
      - `specific.rs` defines traits for components and equalities, parameterised by specific types for given cryptographic mechanisms
      - `general.rs` defines `ComposableCommittedComponent` and `EqualitySpec` in terms of "opaque" types,
        and enables converting specific implementations to general ones by using `FromApi` instances for arguments and `ToApi` instances for return values
    - `api_types.rs` (under `types/`) defines `ToApi` and `FromApi` traits as well as all "general" types used by the framework
  - `src/implementations/`
      - `ccc_graph.rs` defines graph structure, implements API traits using helpers (see below)
      - `components/` implementations of specific components that can be used to construct graphs; the first two can be combined to enable device binding of credentials based on BBS+ signatures with selective-disclosure via the DNC proof system (see `example_graphs` below)
        - `pok_ecdsa_sig_verifies_against_committed_pk.rs`
        - `bbs_sd_dncps.rs`
        - `range_check_bpp.rs`
      - `equalities/` implementations of specific equalities that can be used for equality of values in different components
        - `equal_committed_values_bls_bls.rs` equality of values committed on BLS12-381 curve
        - `equal_committed_values_tom256_bls12381.rs` equality of values committed on Tom256 and BLS12-381 curves, respectively
        - `extraction_traits.rs` traits enabling extracting commitments and commitment keys
      - `registry.rs` enables identifying registered component and equality implementations by name
      - `helpers/` utilities used to implement `CCCGraph` APIs (`setup`/`commit`/`prove`/`verify` at graph level).
  - `src/example_graphs/`
      - `bbs_sd_dncps_single_component.rs` simple example graph comprising a single component supporting BBS+ signature with selective disclosure
      - `bbs_sd_dncps_with_device_binding.rs` graph with two components, adding verification of an ECDSA signature on a challenge message against a committed public key and equalities proving that the public key is signed into two attributes of the BBS+ signature of the first component
      - `bbs_sd_dncps_plus_range_check_and_device_binding.rs` graph combining the above with a range-check component tied to a selected attribute
  - `src/utils/test_support.rs` common utilities for tests
  - `tests/`
      - `api_introspection.rs` tests for graph description/introspection helpers
      - `device_binding_with_proof_system.rs` test demonstrating device binding with the BBS+ selective-disclosure flow in the DNC proof system directly (without using the CCC framework)
      - `graph_based_examples.rs` various positive and negative tests demonstrating construction and use of CCC graphs
      - `graph_operations.rs` tests involving merging and validating graphs
      - `range_check_bpp.rs` simple graph-based test of the range check component

## Tour

The following "tour" of the repository begins with two simple examples showing how to use the API
with a graph that has already been constructed.  It continues with examples showing how to construct
graphs.  Finally, it explains how to construct components and equalities that can be used to
construct new kinds of graphs.

### API

The `CCCGraphApi` trait provides the runtime interface for users of a previously constructed `CCCGraph`.  It enables callers to:
  - inspect a `CCCGraph` (`describe`, `get_component_ids_by_type`, `get_unique_component_id_by_type`) to understand arguments required for the proving lifecycle (these helpers take the `RegisteredComponent` enum; serde keeps the SCREAMING_SNAKE_CASE strings stable for JSON)
  - execute the proving lifecycle (`setup`, `commit`, `prove`, `verify`) using a `CCCGraph`

The `CCCGraphMaker` trait described later is for builders who assemble graphs from registered components and equalities.

Callers to each of the methods in the proving life cycle provide as arguments opaque API types for
each component in the graph via maps keyed by `ComponentId` (identifies a registered component and
contains an `instance_label` that can distinguish multiple versions of the
same component used within a `CCCGraph`). For example, `setup` takes
`AllApiCommonSetupArgs`, which is defined as `HashMap<ComponentId, ApiCommonSetupArgs>`.  Similarly, each method
(other than `verify`) returns per-component opaque API types in maps keyed by `ComponentId`; for example,
`setup` returns `AllApiCommonSetups`, which is defined as `HashMap<ComponentId, ApiCommonSetup>`.

The per-component opaque API type arguments and return values for each method are summarised as follows:
- `setup`: `ApiCommonSetupArgs` → `ApiCommonSetup`
- `commit`: `ApiCommonSetup`, `ApiCommitArgs` → `(ApiCommitmentOpenings, ApiCommitments)`
- `prove`: `ApiCommonSetup`, `ApiCommitmentOpenings`, `ApiCommitments`, `ApiProveArgs` → `ApiComponentProof` (plus an `ApiEqualityProof` for each equality spec in the graph)
- `verify`: `ApiCommonSetup`, `ApiCommitments`, `ApiVerifyArgs`, `ApiProof` → `()` (success is indicated by `Ok(())`)

Each of these methods actually returns `CCCResult<T>` for some `T` encapsulating the values returned
above.

Each component implements `FromApi`/`ToApi` for its concrete arguments and return types so that implementers
can work in native Rust types while uniform, serialisable types are used at the API level, enabling
components dealing with different underlying types to be composed into a graph, and the arguments and
return values to be treated uniformly, for example to enable the API to be exposed via a server.

### Using an existing graph

For a `CCCGraph` `graph`, the proving lifecycle consists of:
- a call to `graph.setup`, providing `ApiCommonSetupArgs` for each component, and receiving `ApiCommonSetup` for each component;
- a call to `graph.commit`, providing `ApiCommonSetup` and `ApiCommitArgs` for each component, and receiving a
`ApiCommitmentOpenings` and `ApiCommitments` for each component
- a call to `graph.prove`, providing the values returned by both the `setup` and `commit` steps, as
  well as `ApiProveArgs`, for each component, and receiving `AllApiProofs`, which contains an `ApiComponentProof` for each component in the graph and an `ApiEqualityProof` for each equality edge
- a call to `graph.verify`, providing for each component: the value returned by the `setup` step, the `ApiCommitments` returned by the `commit` step, `ApiVerifyArgs`, and the values returned by the `prove` step, and receiving `Ok(())` upon success.

To construct the arguments for each of these calls, the caller must know the underlying types
required by each component in the graph, and use `to_api` to convert them to the corresponding
`Api*` type required by the `CCCGraphApi` functions listed above.

The `describe` method assists with this information.  It
documents a graph, providing useful information such as:
- a description of the graph's purpose and the name of a test that exercises it
- for each component, its `ComponentId` and description, the "handles" it supports to
enable equalities to refer to its committed values, and types of arguments needed.
- for each equality edge, its label and description, the `ComponentId`s of the two components it references, and the handles used to refer to the values committed by them

An example of the output of `describe` is shown below.  `ComponentId`s can also be fetched
programmatically.  For example, if the graph is known to contain exactly one component of type
`BBS_SD_DNCPS`, `graph.get_unique_component_id_by_type(BBS_SD_DNCPS)` will provide the full
`ComponentId`.

The best way to understand the proving flow using a graph is to follow an example.
There are some pre-constructed graphs in [example_graphs](./src/example_graphs).  Each example
implements the `SetupCCCGraph` trait by defining a type for setup arguments, and a function that
takes setup arguments and returns a graph.  Each one has a doctest demonstrating its use; see below
for more tests using each of them.

The `bbs_sd_dncps_disclose_one_integer_self_contained` test in
[graph_based_examples.rs](./tests/graph_based_examples.rs) provides a self-contained example
demonstrating the use of a simple graph
[`BbsSdDncps`](./src/example_graphs/bbs_sd_dncps_single_component.rs),
that supports signing a number of messages into a BBS+ signature (via the DNC proof system) and proving knowledge of
a signature, optionally disclosing some of the messages.

The same test is repeated in test `bbs_sd_dncps_disclose_one_integer`, but using a
`GraphBundleForTest`, which contains a graph and role-specific arguments for the `setup`, `commit`, `prove`
and `verify` steps.  The test builds the `GraphBundleForTest` using a function
`build_graph_bundle_for_bbs_sd_dncps_with_integer_attr`, which enables more variations on the test to be
expressed succinctly.

Graphs with more components and equalities between them and tests that demonstrate their use
are discussed below.

### Building graphs from existing components and equalities

Each example graph in [example_graphs](./src/example_graphs)
begins with an empty graph and uses the methods of the [`CCCGraphMaker`](./src/api.rs) trait to add
registered components and equalities as needed.

The `device_binding_and_bbs_sd_dncps_happy_path` test demonstrates use of an
example graph:
[`BbsSdDncpsWithDeviceBinding`](./src/example_graphs/bbs_sd_dncps_with_device_binding.rs)
that comprises two components:

- an `ESVCPK` (Ecdsa Signature
Verifies against Committed Public Key) that proves knowledge of an ECDSA public key and a signature
on a challenge message that verifies against this public key, and
- a `BBS_SD_DNCPS` component (as described above).

This graph also has two equality edges, one to prove equality of the "x" component of the public key
with one attribute signed in the BBS+ signature and similarly one for the "y" component.  If an
Issuer signs these attributes for the public key of a Holder's device, this enables "device
binding", i.e., the Holder can prove that it has control of the device for which the signature was
issued.

To enable equality edges to refer to committed values, each `ComposableCommittedComponent` (more
precisely, `SpecificComposableCommittedComponent`; see [below](#creating-new-components)) has a
`CommitmentHandle` type which enables referring to the commitments created for each component.  For
example, the `ESVCPK` component has `PkX` and `PkY`, which refer to the x and y components of the
committed public key, and the `BBS_SD_DNCPS` component as commit handles `BbsSdDncpsCommitmentHandle(i)` for
a commitment to the message signed at index `i`.

The output of the `describe` function for the graph used in this test is shown here:

```
Description: BBS+ selective disclosure with device binding (DNC proof system)
Exercised by test: device_binding_and_bbs_sd_dncps_happy_path
Components:
  ComponentId: BBS_SD_DNCPS-suffix
    - BBS+ selective disclosure component via the DNC proof system committing to selected attributes of a credential
    - handles: BbsSdDncpsCommitmentHandle(index)
    - types:
        setup: bbs_sd_dncps::BbsSdDncpsCommonSetupArgs
        commit_args: bbs_sd_dncps::BbsSdDncpsCommitArgs
        prove_args: bbs_sd_dncps::BbsSdDncpsProveArgs
        verify_args: bbs_sd_dncps::BbsSdDncpsVerifyArgs
        handle: bbs_sd_dncps::BbsSdDncpsCommitmentHandle
  ComponentId: ESVCPK-suffix
    - Proof of knowledge of an ECDSA signature on a known challenge that verifies against a committed public key
    - handles: PkX, PkY
    - types:
        setup: pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKCommonSetupArgs
        commit_args: affine::Affine<ark_secp256r1::curves::Config>
        prove_args: pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKProverArgs
        verify_args: pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKVerifyArgs
        handle: pok_ecdsa_sig_verifies_against_committed_pk::ESVCPKCommitmentHandle
Equalities:
  Equality ID: EqualityEcdsaPubKeyAndBbsSdDncMsgPs-PK_X-suffix
    - Equality of committed values between ESVCPK (TOM256) and BBS_SD_DNCPS (BLS12-381)
    - endpoints:
      * ESVCPK-suffix (handle: PkX)
      * BBS_SD_DNCPS-suffix (handle: BbsSdDncpsCommitmentHandle(3))
  Equality ID: EqualityEcdsaPubKeyAndBbsSdDncMsgPs-PK_Y-suffix
    - Equality of committed values between ESVCPK (TOM256) and BBS_SD_DNCPS (BLS12-381)
    - endpoints:
      * ESVCPK-suffix (handle: PkY)
      * BBS_SD_DNCPS-suffix (handle: BbsSdDncpsCommitmentHandle(4))
```

### Combining existing graphs

The [`merge_disjoint_maps`](./src/utils/graph_utils.rs) function merges two existing graphs,
provided they have disjoint keys.  Note that the new graph will not be connected until an edge is
added between components in the original graphs.  The `verify` function uses `validate_connected` to
ensure that the graph is connected; note that this does not ensure all intended equalities are
present, but will catch some omissions.

The `merge_two_graphs_and_equalize_bbs_sd_dncps_attributes` test constructs two
`BbsSdDncpsWithDeviceBinding` graphs, merges them, and adds an equality edge
requiring an attribute in one to be equal to an attribute in the other.  Several variations check
that verification fails under various erroneous conditions.

### Creating and registering new components

Creating a new component entails implementing the
[`SpecificComposableCommittedComponent`](./src/interfaces/specific.rs) trait.  To implement that trait, implementation-specific types must be defined for:
`ValueType`,
`RandomnessType`,
`CommitmentType`,
`CommonSetupArgs`,
`CommonSetup`,
`CommitArgs`,
`CommitmentHandle`,
`ProveArgs`,
`Proof`,
`VerifyArgs` and
`VerifyReturn`.

`ValueType` is the type of values that the component will prove properties about, `RandomnessType`
is the type that it will use to blind values to produce commitments, and `CommitmentType` is the
 type of commitments that it will produce.

These types must implement the required trait bounds, including `ToApi`/`FromApi` conversions
so that callers can pass and receive opaque API values, while specific components can work with their concrete Rust types.
Implementers of `SpecificComposableCommittedComponent` do not need to handle conversions
between opqaue API types and the component's concrete types.  The
`ComposableCommittedComponent::from_specific_component` method converts a
`SpecificComposableCommittedComponent` to a `ComposableCommittedComponent`, handling all needed
conversions.  That method is parameterised by the `SpecificComponent` and its `ValueType`,
`RandomnessType`, `CommitmentType` and takes as arguments a brief description of the component and a
list of strings that document the `CommitmentHandle`(s) it uses to identify values be committed.

Before a `ComposableCommittedComponent` constructed in this way can be included in a `CCCGraph`, it
must be registered.  This entails adding a new variant to the
[`RegisteredComponent`](./src/implementations/registry.rs) enum, and adding the required case to
`RegisteredComponent::get_component`; by convention, each `SpecificComposableCommittedComponent`
provides a function to produce a `ComposableCommittedComponent` using `from_specific_component`,
which is called by the relevant case of `get_component`.

Note that the CCC framework does not prescribe or limit how commitments are produced, nor how proofs
over committed values are created and verified.  For some examples:

* The component registered as `BBS_SD_DNCPS` uses the DNC [proof system](../proof_system) to create and verify proofs of
knowledge of BBS signatures with disclosed and committed values (see the
`SpecificComposableCommittedComponent` impl for `BbsSdDncps` in
[bbs_sd_dncps.rs](./src/implementations/components/bbs_sd_dncps.rs)).

* The component registered as `ESVCPK` uses types from
[equality_across_groups](../equality_across_groups) together with DNC's
[implementation](../utils/src/transcript.rs) of [Merlin transcripts](https://merlin.cool/),
based on the example [here](../equality_across_groups/src/pok_ecdsa_pubkey.rs) (see the impl for `EcdsaSignCommittedPublicKey` in
[pok_ecdsa_sig_verifies_against_committed_pk.rs](./src/implementations/components/pok_ecdsa_sig_verifies_against_committed_pk.rs)).

* The component registered as `RANGE_CHECK_BPP` uses DNC's [bulletproofs_plus_plus](../bulletproofs_plus_plus) crate 
(see the impl for `RangeCheckBpp` in [range_check_bpp.rs](./src/implementations/components/range_check_bpp.rs)).

### Creating and registering new equalities

Creating a new equality entails implementing the
[`SpecificEqualityOfCommittedValues`](./src/interfaces/specific.rs) trait, which is parameterised by
two `SpecificComposableCommittedComponent`s and a `Proof` type for proofs that two committed values
(one for each of the components) are equal.

The `EqualityOfCommittedValues::from_components_and_equality` method converts a
`SpecificEqualityOfCommittedValues` to an `EqualityOfCommittedValues`, handling all needed
conversions.  That method is parameterised by two `SpecificComposableCommittedComponent`s,
and a `SpecificEqualityOfCommittedValues` for proving equivalence of their respective `ValueType`s.

Before a `ComposableCommittedComponent` constructed in this way can be included in a `CCCGraph`, it
must be registered by adding a new variant to the
[`RegisteredEquality`](./src/implementations/registry.rs) enum and using the
`EqualityOfCommittedValues::from_components_and_equality` function (by convention via a function
provided for the purpose of creating an `EqualityOfCommittedValues`).

As with components, the CCC framework does not prescribe or limit how equalities of
committed values are proved or verified.  For some examples:

* The equality registered as `EqualityEcdsaPubKeyAndBbsSdDncMsgPs` uses the `equality_across_groups` crate to prove that
a value committed on the `Tom256` curve by an `EcdsaSignCommittedPublicKey` specific component and a value
committed on the `Bls12-381` curve by a `BbsSdDncps` specific component are equal, using the `EqualityTomBls`
specific equality.

* The equalities registered as `EqualityBbsSdDncpsRange` and `EqualityByEqualCommittedValuesBlsBls`,
respectively, both prove that two values committed on the `Bls12-381` curve are equal.  
These both use the same specific equality `EqualityByEqualCommittedValuesBlsBls`, which is possible
because the `BbsSdDncps` and `RangeCheckBpp` both use the same underlying types for commitment keys,
randomness and commitments.
Because these are wrapped in different types at the component level,
`EqualityByEqualCommittedValuesBlsBls` requires the `CommonSetup` and `CommitmentType` types of the
components whose values are to be proved equal to implement special "extraction" traits that enable
accessing the commitment key and commitments from those types.

## Quick summary of all tests

- In [tests/graph_based_examples.rs](./tests/graph_based_examples.rs):
    - `bbs_sd_dncps_disclose_one_integer_self_contained`: self-contained BBS+ selective-disclosure (BBS_SD_DNCPS, via DNC proof system) demo; discloses one integer.
    - `bbs_sd_dncps_disclose_one_integer`: same test again, demonstrating role-based graph "bundle" approach.
    - `bbs_sd_dncps_no_disclose`: selective-disclosure flow with no committed attributes.
    - `bbs_sd_dncps_commit_one_message`: commits a single message without disclosure.
    - `bbs_sd_dncps_disclose_and_commit`: mixes disclosed and committed messages.
    - `device_binding_and_bbs_sd_dncps_happy_path`: combined device-binding + BBS_SD_DNCPS graph.
    - `merge_two_graphs_and_equalize_bbs_sd_dncps_attributes`: merges two BBS_SD_DNCPS graphs and proves equality of two equal messages.
    - `merge_fails_when_values_differ`: same merge with differing values; expects equality proof to fail.
    - `merge_fails_when_index_not_committed`: same merge but does not commit the message to be proved equal; expects failure.
    - `bbs_sd_dncps_value_with_device_binding_and_range_check_happy_path`: adds device binding and a range check for a value equal to a signed message.
    - `bbs_sd_dncps_value_with_device_binding_and_range_check_value_out_of_range_equal`: value equals the range input but is out of bounds; range proof fails.
    - `bbs_sd_dncps_value_with_device_binding_and_range_check_value_out_of_range_not_equal`: value differs and is out of bounds; equality proof fails.
    - `detects_invalid_graph_edge`: adding an equality spec referencing a missing component is rejected.
- [tests/api_introspection.rs](./tests/api_introspection.rs):
    - `describe_single_component_graph`: verifies describe output for the single-component BBS_SD_DNCPS graph.
    - `describe_multi_component_graph_with_equalities`: checks describe output for the device-binding graph with two equalities.
    - `describe_three_component_graph_with_range_check`: checks describe output for the device-binding + range-check graph.
    - `unique_component_errors_when_missing_or_duplicate`: ensures helper errors when component types are missing or duplicated.
- [tests/range_check_bpp.rs](./tests/range_check_bpp.rs):
    - `range_check_bpp_happy_path`: RangeCheckBpp graph proves value 42 within [10,100].
    - `range_check_bpp_out_of_range_fails`: committing value 150 causes prove step to error as out of bounds.
- [tests/device_binding_with_proof_system.rs](./tests/device_binding_with_proof_system.rs):
    - `test_device_binding_with_proof_system`: end-to-end device-binding flow linking ECDSA committed key to BBS+ (via DNC proof system) attributes via equality proofs; verifies Tom commitment proof, BLS proof,
      and both equalities.
- [tests/graph_operations.rs](./tests/graph_operations.rs):
    - `merge_disjoint_succeeds`: merging disjoint graphs duplicates components/equalities; validate passes, connected check fails as expected.
    - `merge_fails_on_component_collision`: merge_disjoint errors on component label collision.
    - `merge_fails_on_equality_spec_collision`: merge_disjoint errors on duplicate equality spec labels.
    - `validate_connected_detects_disconnected_graph`: validate_connected flags disconnected graph; passes after adding an equality to connect the isolated component.
