cc_binary(
    name = "fib_air_test",
    srcs = [
        "fibonacci.cc",
        "//src/starkware/stark:committed_trace.h",
        "//src/starkware/stark:composition_oracle.h",
        "//src/starkware/stark:stark.h",
        "//src/starkware/stark:stark.cc",
        "//src/starkware/stark:test_utils.h",
        "//src/starkware/stark:utils.h",
        "//src/starkware/stark:utils.inl",
        "//src/starkware/air:air.h",
        "//src/starkware/air:test_utils.h",
        "//src/starkware/air:trace.h",
        "//src/starkware/air:trace_context.h",
        "//src/starkware/air/components:trace_generation_context.h",
        "//src/starkware/air/components:virtual_column.h",
        "//src/starkware/air/components/bit_unpacking:bit_unpacking.h",
        "//src/starkware/air/components/ec_subset_sum:ec_subset_sum.h",
        "//src/starkware/air/components/ec_subset_sum:ec_subset_sum.inl",
        "//src/starkware/air/components/permutation:multi_column_permutation.h",
        "//src/starkware/air/components/permutation:multi_column_permutation.inl",
        "//src/starkware/air/components/permutation:permutation.h",
        "//src/starkware/air/components/permutation:permutation.inl",
        "//src/starkware/air/components/permutation:permutation_dummy_air.h",
        "//src/starkware/air/components/permutation:permutation_dummy_air.inl",
        "//src/starkware/air/components/permutation:permutation_trace_context.h",
        "//src/starkware/air/degree_three_example:degree_three_example_trace_context.h",
        "//src/starkware/air/fibonacci:fibonacci_trace_context.h",
        "//src/starkware/algebra:big_int.h",
        "//src/starkware/algebra:big_int.inl",
        "//src/starkware/algebra:field_element_base.h",
        "//src/starkware/algebra:field_element_base.inl",
        "//src/starkware/algebra:field_operations.h",
        "//src/starkware/algebra:field_operations.inl",
        "//src/starkware/algebra:polynomials.h",
        "//src/starkware/algebra:polynomials.inl",
        "//src/starkware/algebra:uint128.h",
        "//src/starkware/algebra/domains:list_of_cosets.h",
        "//src/starkware/algebra/domains:multiplicative_group.h",
        "//src/starkware/algebra/domains:ordered_group.h",
        "//src/starkware/algebra/elliptic_curve:elliptic_curve.h",
        "//src/starkware/algebra/elliptic_curve:elliptic_curve.inl",
        "//src/starkware/algebra/elliptic_curve:elliptic_curve_constants.h",
        "//src/starkware/algebra/fft:details.h",
        "//src/starkware/algebra/fft:details.inl",
        "//src/starkware/algebra/fft:fft_with_precompute.h",
        "//src/starkware/algebra/fft:fft_with_precompute.inl",
        "//src/starkware/algebra/fft:multiplicative_fft.h",
        "//src/starkware/algebra/fft:multiplicative_fft.inl",
        "//src/starkware/algebra/fft:multiplicative_group_ordering.h",
        "//src/starkware/algebra/fft:transpose.h",
        "//src/starkware/algebra/fields:big_prime_constants.h",
        "//src/starkware/algebra/fields:extension_field_element.h",
        "//src/starkware/algebra/fields:extension_field_element.inl",
        "//src/starkware/algebra/fields:fraction_field_element.h",
        "//src/starkware/algebra/fields:fraction_field_element.inl",
        "//src/starkware/algebra/fields:long_field_element.h",
        "//src/starkware/algebra/fields:prime_field_element.h",
        "//src/starkware/algebra/fields:prime_field_element.inl",
        "//src/starkware/algebra/fields:test_field_element.h",
        "//src/starkware/algebra/fields:test_field_element.inl",
        "//src/starkware/algebra/lde:cached_lde_manager.h",
        "//src/starkware/algebra/lde:lde.h",
        "//src/starkware/algebra/lde:lde_manager_impl.h",
        "//src/starkware/algebra/lde:lde_manager_impl.inl",
        "//src/starkware/algebra/lde:multiplicative_lde.h",
        "//src/starkware/algebra/lde:multiplicative_lde.inl",
        "//src/starkware/algebra/polymorphic:field.h",
        "//src/starkware/algebra/polymorphic:field.inl",
        "//src/starkware/algebra/polymorphic:field_element.h",
        "//src/starkware/algebra/polymorphic:field_element.inl",
        "//src/starkware/algebra/polymorphic:field_element_span.h",
        "//src/starkware/algebra/polymorphic:field_element_span.inl",
        "//src/starkware/algebra/polymorphic:field_element_vector.h",
        "//src/starkware/algebra/polymorphic:field_element_vector.inl",
        "//src/starkware/algebra/utils:invoke_template_version.h",
        "//src/starkware/channel:annotation_scope.h",
        "//src/starkware/channel:channel.h",
        "//src/starkware/channel:channel_statistics.h",
        "//src/starkware/channel:noninteractive_prover_channel.h",
        "//src/starkware/channel:noninteractive_verifier_channel.h",
        "//src/starkware/channel:prover_channel.h",
        "//src/starkware/channel:verifier_channel.h",
        "//src/starkware/commitment_scheme:caching_commitment_scheme.h",
        "//src/starkware/commitment_scheme:commitment_scheme.h",
        "//src/starkware/commitment_scheme:packaging_commitment_scheme.h",
        "//src/starkware/commitment_scheme:packer_hasher.h",
        "//src/starkware/commitment_scheme:parallel_table_prover.h",
        "//src/starkware/commitment_scheme:row_col.h",
        "//src/starkware/commitment_scheme:table_prover.h",
        "//src/starkware/commitment_scheme:table_prover_impl.h",
        "//src/starkware/commitment_scheme:table_verifier.h",
        "//src/starkware/commitment_scheme:table_verifier_impl.h",
        "//src/starkware/commitment_scheme/merkle:merkle.h",
        "//src/starkware/commitment_scheme/merkle:merkle_commitment_scheme.h",
        "//src/starkware/composition_polynomial:composition_polynomial.h",
        "//src/starkware/composition_polynomial:composition_polynomial.inl",
        "//src/starkware/composition_polynomial:multiplicative_neighbors.h",
        "//src/starkware/composition_polynomial:multiplicative_neighbors.inl",
        "//src/starkware/composition_polynomial:periodic_column.h",
        "//src/starkware/composition_polynomial:periodic_column.inl",
        "//src/starkware/crypt_tools:blake2s.h",
        "//src/starkware/crypt_tools:blake2s.inl",
        "//src/starkware/crypt_tools:invoke.h",
        "//src/starkware/crypt_tools:keccak_256.h",
        "//src/starkware/crypt_tools:keccak_256.inl",
        "//src/starkware/crypt_tools:masked_hash.h",
        "//src/starkware/crypt_tools:pedersen.h",
        "//src/starkware/crypt_tools:pedersen.inl",
        "//src/starkware/crypt_tools:utils.h",
        "//src/starkware/crypt_tools/hash_context:hash_context.h",
        "//src/starkware/crypt_tools/hash_context:pedersen_hash_context.h",
        "//src/starkware/error_handling:error_handling.h",
        "//src/starkware/error_handling:test_utils.h",
        "//src/starkware/fft_utils:fft_bases.h",
        "//src/starkware/fft_utils:fft_bases.inl",
        "//src/starkware/fft_utils:fft_domain.h",
        "//src/starkware/fft_utils:fft_group.h",
        "//src/starkware/fft_utils:fft_group.inl",
        "//src/starkware/fri:fri_parameters.h",
        "//src/starkware/math:math.h",
        "//src/starkware/proof_system:proof_system.h",
        "//src/starkware/randomness:hash_chain.h",
        "//src/starkware/randomness:prng.h",
        "//src/starkware/stl_utils:containers.h",
        "//src/starkware/utils:attributes.h",
        "//src/starkware/utils:bit_reversal.h",
        "//src/starkware/utils:json.h",
        "//src/starkware/utils:json.inl",
        "//src/starkware/utils:maybe_owned_ptr.h",
        "//src/starkware/utils:profiling.h",
        "//src/starkware/utils:serialization.h",
        "//src/starkware/utils:serialization.inl",
        "//src/starkware/utils:task_manager.h",
        "//src/starkware/utils:task_manager.inl",
        "//src/starkware/utils:to_from_string.h",
        "//src/third_party/blake2:blake2.h",
        "//src/third_party/blake2:blake2-impl.h",
        "//src/third_party/cppitertools:range.hpp",
        "//src/third_party/cppitertools:reversed.hpp",
        "//src/third_party/cppitertools:zip.hpp",
        "//src/third_party/cppitertools/internal:iter_tuples.hpp",
        "//src/third_party/cppitertools/internal:iterator_wrapper.hpp",
        "//src/third_party/cppitertools/internal:iterbase.hpp",
        "//src/third_party/gsl:gsl-lite.hpp",
        "//src/third_party/jsoncpp/json:json.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//src/starkware/stark",
        "//src/starkware/air/components/permutation:permutation_dummy_air_lib",
        "//src/starkware/air/degree_three_example:degree_three_example_air_lib",
        "//src/starkware/air/fibonacci:fibonacci_air_lib",
        "//src/starkware/commitment_scheme:commitment_scheme_builder",
        "//src/starkware/commitment_scheme/merkle:merkle_tree",
        "//src/starkware/gtest:starkware_gtest",
        "//src/starkware/proof_system",
        "//src/third_party",
    ],
)
