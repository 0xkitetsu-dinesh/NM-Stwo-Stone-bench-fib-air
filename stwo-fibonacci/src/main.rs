use num_traits::One;

use stwo_prover::core::backend::cpu::CpuCircleEvaluation;
use stwo_prover::core::channel::{Blake2sChannel, Channel};
use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::fields::{ IntoSlice};
use stwo_prover::core::poly::circle::{CanonicCoset, CircleEvaluation};
use stwo_prover::core::poly::BitReversedOrder;
use stwo_prover::core::prover::{prove, verify, ProvingError, StarkProof, VerificationError};
use stwo_prover::core::vcs::blake2_hash::Blake2sHasher;
use stwo_prover::core::vcs::hasher::Hasher;

use stwo_prover::core::fields::m31::M31;

mod fib_air;
mod fib_component;

use fib_air::FibonacciAir;
use fib_component::FibonacciComponent;

pub struct Fibonacci {
    pub air: FibonacciAir,
}

impl Fibonacci {
    pub fn new(log_size: u32, claim: BaseField) -> Self {
        let component = FibonacciComponent::new(log_size, claim);
        Self {
            air: FibonacciAir::new(component),
        }
    }

    pub fn get_trace(&self) -> CpuCircleEvaluation<BaseField, BitReversedOrder> {
        // Trace.
        let trace_domain = CanonicCoset::new(self.air.component.log_size);
        // TODO(AlonH): Consider using Vec::new instead of Vec::with_capacity throughout file.
        let mut trace = Vec::with_capacity(trace_domain.size());

        // Fill trace with fibonacci squared.
        let mut a = BaseField::one();
        let mut b = BaseField::one();
        for _trace_id in 0..trace_domain.size() {
            // println!("<{}> {} {} {}", _trace_id, a, b, a+b);
            trace.push(a);
            // let tmp = a.square() + b.square();
            let tmp = a + b;
            a = b;
            b = tmp;
        }

        // Returns as a CircleEvaluation.
        CircleEvaluation::new_canonical_ordered(trace_domain, trace)
    }

    pub fn prove(&self) -> Result<StarkProof, ProvingError> {
        let trace = self.get_trace();
        let channel = &mut Blake2sChannel::new(Blake2sHasher::hash(BaseField::into_slice(&[self
            .air
            .component
            .claim])));
        prove(&self.air, channel, vec![trace])
    }

    pub fn verify(&self, proof: StarkProof) -> Result<(), VerificationError> {
        let channel = &mut Blake2sChannel::new(Blake2sHasher::hash(BaseField::into_slice(&[self
            .air
            .component
            .claim])));
        verify(proof, &self.air, channel)
    }
}


fn main() {
    const FIB_LOG_SIZE: u32 = 8;
    let fib = Fibonacci::new(FIB_LOG_SIZE, M31::from_u32_unchecked(1282134762));

    // println!("fib trace {:#?}", fib.get_trace());
    // println!("fib trace values.length {:#?}", fib.get_trace().values.len());

    println!("Fib series - {}",1<<FIB_LOG_SIZE) ;

    let start_time  = std::time::Instant::now();
    
    let start_prover_time = start_time.elapsed();
    let proof = fib.prove().unwrap();
    let end_prover_time = start_time.elapsed();
    println!("fib.prove() took {:?}", end_prover_time - start_prover_time);

    fib.verify(proof).unwrap();
    let end_verify_time = start_time.elapsed();
    println!("fib.verify(proof) took {:?}", end_verify_time - end_prover_time);
}