#include "starkware/stark/stark.h"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <chrono>
#include <time.h>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "starkware/air/components/permutation/permutation_dummy_air.h"
#include "starkware/air/components/permutation/permutation_trace_context.h"
#include "starkware/air/degree_three_example/degree_three_example_air.h"
#include "starkware/air/degree_three_example/degree_three_example_trace_context.h"
#include "starkware/air/fibonacci/fibonacci_air.h"
#include "starkware/air/fibonacci/fibonacci_trace_context.h"
#include "starkware/air/test_utils.h"
#include "starkware/air/trace_context.h"
#include "starkware/algebra/fields/extension_field_element.h"
#include "starkware/algebra/fields/test_field_element.h"
#include "starkware/channel/annotation_scope.h"
#include "starkware/channel/noninteractive_prover_channel.h"
#include "starkware/channel/noninteractive_verifier_channel.h"
#include "starkware/commitment_scheme/commitment_scheme_builder.h"
#include "starkware/commitment_scheme/table_prover_impl.h"
#include "starkware/commitment_scheme/table_verifier_impl.h"
#include "starkware/crypt_tools/blake2s.h"
#include "starkware/crypt_tools/keccak_256.h"
#include "starkware/error_handling/test_utils.h"
#include "starkware/proof_system/proof_system.h"
#include "starkware/stark/test_utils.h"
#include "starkware/stark/utils.h"
#include "starkware/stl_utils/containers.h"
#include "starkware/utils/maybe_owned_ptr.h"

using namespace starkware; // NOLINT
// using StarkField252 = PrimeFieldElement<252, 0>;
// using FibAirT = FibonacciAir<StarkField252>;
// using FibTraceContextT = FibonacciTraceContext<StarkField252>;


using FibAirT = FibonacciAir<TestFieldElement>;
using FibTraceContextT = FibonacciTraceContext<TestFieldElement>;

std::vector<size_t> DrawFriStepsList(const size_t log_degree_bound,
                                     Prng *prng) {
  if (prng == nullptr) {
    return {3, 3, 1, 1};
  }
  std::vector<size_t> res;
  for (size_t curr_sum = 0; curr_sum < log_degree_bound;) {
    res.push_back(prng->UniformInt<size_t>(1, log_degree_bound - curr_sum));
    curr_sum += res.back();
  }
  ASSERT_RELEASE(Sum(res) == log_degree_bound,
                 "The sum of all steps must be the log of the degree bound.");
  return res;
}

template <typename FieldElementT>
StarkParameters GenerateParameters(std::unique_ptr<Air> air, Prng *prng,
                                   size_t proof_of_work_bits = 15,
                                   bool use_extension_field = false) {
  // Field used.
  const Field field(Field::Create<FieldElementT>());
  const size_t trace_length = air->TraceLength();
  uint64_t degree_bound =
      air->GetCompositionPolynomialDegreeBound() / trace_length;

  const auto log_n_cosets =
      (prng == nullptr ? 4
                       : prng->UniformInt<size_t>(Log2Ceil(degree_bound), 6));
  const size_t log_coset_size = Log2Ceil(trace_length);
  const size_t n_cosets = Pow2(log_n_cosets);
  const size_t log_evaluation_domain_size = log_coset_size + log_n_cosets;

  // Fri steps - hard-coded pattern for this tests suit.
  const size_t log_degree_bound = log_coset_size;
  const std::vector<size_t> fri_step_list =
      DrawFriStepsList(log_degree_bound, prng);

  // Bases used by FRI.
  const FieldElementT offset =
      (prng == nullptr ? FieldElementT::One()
                       : FieldElementT::RandomElement(prng));
  FftBasesImpl<FftMultiplicativeGroup<FieldElementT>> bases =
      MakeFftBases(log_evaluation_domain_size, offset);

  // FRI parameters.
  FriParameters fri_params{/*fri_step_list=*/fri_step_list,
                           /*last_layer_degree_bound=*/1,
                           /*n_queries=*/30,
                           /*fft_bases=*/UseMovedValue(std::move(bases)),
                           /*field=*/field,
                           /*proof_of_work_bits=*/proof_of_work_bits};

  return StarkParameters(field, use_extension_field, n_cosets, trace_length,
                         TakeOwnershipFrom(std::move(air)),
                         UseMovedValue(std::move(fri_params)));
}

template <typename HashT, typename FieldElementT>
std::unique_ptr<TableProver>
MakeTableProver(uint64_t n_segments, uint64_t n_rows_per_segment,
                size_t n_columns, ProverChannel *channel,
                size_t n_tasks_per_segment, size_t n_layer,
                size_t n_verifier_friendly_commitment_layers) {
  return GetTableProverFactory<HashT>(channel, FieldElementT::SizeInBytes(),
                                      n_tasks_per_segment, n_layer,
                                      n_verifier_friendly_commitment_layers,
                                      CommitmentHashes(HashT::HashName()))(
      n_segments, n_rows_per_segment, n_columns);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <secret> <trace_length> <fibonacci_claim_index>" << std::endl;
        return 1;
    }

    TestFieldElement secret = TestFieldElement::FromUint(std::stoull(argv[1]));
    uint64_t trace_length = std::stoull(argv[2]);
    uint64_t fibonacci_claim_index = std::stoull(argv[3]);


  TestFieldElement claimed_fib =
      FibAirT::PublicInputFromPrivateInput(secret, fibonacci_claim_index);
  std::cout << "claimed_fib - "<< claimed_fib << std::endl;

  // Construct AIR
  auto air = FibAirT(trace_length, fibonacci_claim_index, claimed_fib);
  const Prng channel_prng = Prng();
  NoninteractiveProverChannel prover_channel =
      NoninteractiveProverChannel(channel_prng.Clone());

  Prng prng = Prng();
  StarkProverConfig stark_config = StarkProverConfig::InRam();

  StarkParameters stark_params = GenerateParameters<TestFieldElement>(
      std::make_unique<FibAirT>(trace_length, fibonacci_claim_index,
                                claimed_fib),
      &prng);

  TableProverFactory table_prover_factory =
      [&](uint64_t n_segments, uint64_t n_rows_per_segment, size_t n_columns) {
        const size_t n_verifier_friendly_commitment_layers = 0;
        return MakeTableProver<Keccak256, TestFieldElement>(
            n_segments, n_rows_per_segment, n_columns, &prover_channel,
            stark_config.table_prover_n_tasks_per_segment,
            stark_config.n_out_of_memory_merkle_layers,
            n_verifier_friendly_commitment_layers);
      };

  // Prove

  StarkProver stark_prover(UseOwned(&prover_channel),
                           UseOwned(&table_prover_factory),
                           UseOwned(&stark_params), UseOwned(&stark_config),false);

  auto start_prover_time = std::chrono::high_resolution_clock::now();

  stark_prover.ProveStark(std::make_unique<FibTraceContextT>(
      UseOwned(&air), secret, fibonacci_claim_index));
    
  auto end_prover_time = std::chrono::high_resolution_clock::now();


  auto proof = prover_channel.GetProof();
  const std::optional<std::vector<std::string>> prover_annotations =
      prover_channel.GetAnnotations();

  NoninteractiveVerifierChannel verifier_channel(channel_prng.Clone(), proof);
  if (prover_annotations) {
    verifier_channel.SetExpectedAnnotations(*prover_annotations);
  }

  const size_t n_verifier_friendly_commitment_layers = 0;
  TableVerifierFactory table_verifier_factory =
      [&verifier_channel](const Field &field, uint64_t n_rows,
                          uint64_t n_columns) {
        return MakeTableVerifier<Keccak256, TestFieldElement>(
            field, n_rows, n_columns, &verifier_channel,
            n_verifier_friendly_commitment_layers);
      };
  StarkVerifier stark_verifier(UseOwned(&verifier_channel),
                               UseOwned(&table_verifier_factory),
                               UseOwned(&stark_params),false);

  auto start_verifier_time = std::chrono::high_resolution_clock::now();

  stark_verifier.VerifyStark();

  auto end_verifier_time = std::chrono::high_resolution_clock::now();



    auto prover_time = std::chrono::duration_cast<std::chrono::microseconds>(end_prover_time - start_prover_time);
    auto verifier_time = std::chrono::duration_cast<std::chrono::microseconds>(end_verifier_time - start_verifier_time);

    std::cout<<"STONE fibonacci_claim_index - "<<fibonacci_claim_index << ", claimed_fib - "<<claimed_fib<<std::endl;

    std::cout<<"Prover Time - "<< prover_time.count() << " microseconds" << std::endl;

    std::cout<<"Verifier Time - "<< verifier_time.count() << " microseconds"<< std::endl;

  return 0;
}