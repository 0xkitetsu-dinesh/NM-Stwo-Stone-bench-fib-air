bench_fib:fib_stwo fib_stone

fib_stwo:
	@echo "fib stwo air"
	RUSTUP_TOOLCHAIN="nightly-2024-01-04" cargo build --manifest-path /home/ubuntu/dinesh/NM-Stwo-Stone-bench-fib-air/stwo_fibonacci/Cargo.toml --release
	@time ./stwo_fibonacci/target/release/stwo_fibonacci
	@echo "\n"

fib_stone:
	@echo "fib stone air"
	cd stone_prover && bazel build //...
	@time stone_prover/build/bazelbin/e2e_test/FibAir/fib_air_test 1 256 255
	@echo "\n"
