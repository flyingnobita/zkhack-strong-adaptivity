#![allow(unused, unreachable_code)]
use ark_ed_on_bls12_381::Fr;
use ark_ff::Field;
use ark_std::UniformRand;
use prompt::{puzzle, welcome};
use rand::Rng;
use strong_adaptivity::prove;
use strong_adaptivity::utils::b2s_hash_to_field;
use strong_adaptivity::verify;
use strong_adaptivity::ProofCommitment;
use strong_adaptivity::ProofResponse;
use strong_adaptivity::Witness;
use strong_adaptivity::PUZZLE_DESCRIPTION;
use strong_adaptivity::{data::puzzle_data, Instance, Proof};

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let ck = puzzle_data();
    let rng = &mut rand::thread_rng();

    // Original Protocol
    // make 2 commitments of same message, ensure that it verifies
    // let a_1 = Fr::rand(rng);
    // let (comm_1, r_1) = ck.commit_with_rng(a_1, rng);
    // let (comm_2, r_2) = ck.commit_with_rng(a_1, rng);
    // let instance = Instance { comm_1, comm_2 };
    // let witness = Witness { a: a_1, r_1, r_2 };
    // let proof = prove(&ck, &instance, &witness, rng);
    // assert!(verify(&ck, &instance, &proof), "Verify failed");

    let (instance, witness, proof): (Instance, (Fr, Fr, Fr, Fr), Proof) = {
        let r_rho = Fr::rand(rng);
        let r_tau = Fr::rand(rng);
        let (comm_rho, rho) = ck.commit_with_rng(r_rho, rng);
        let (comm_tau, tau) = ck.commit_with_rng(r_tau, rng);
        let commitment = ProofCommitment { comm_rho, comm_tau };

        // Compute challenge = CommitKey and (C_rho + C_tau)
        let challenge = b2s_hash_to_field(&(ck, commitment));

        let a_1 = Fr::rand(rng);
        let (comm_1, r_1) = ck.commit_with_rng(a_1, rng);
        let a_2 = a_1 + (r_rho - r_tau) / challenge;
        let (comm_2, r_2) = ck.commit_with_rng(a_2, rng);

        let instance = Instance { comm_1, comm_2 };
        let witness = (a_1, r_1, a_2, r_2);

        let s = r_rho + challenge * a_1;
        let u = rho + challenge * r_1;
        let t = tau + challenge * r_2;
        let response = ProofResponse { s, u, t };

        let proof = Proof {
            commitment,
            response,
        };

        (instance, witness, proof)
    };

    let (a_1, r_1, a_2, r_2) = witness;

    assert!(verify(&ck, &instance, &proof));
    // Check that commitments are correct
    assert_eq!(
        ck.commit_with_explicit_randomness(a_1, r_1),
        instance.comm_1
    );
    assert_eq!(
        ck.commit_with_explicit_randomness(a_2, r_2),
        instance.comm_2
    );
    // Check that messages are unequal
    assert_ne!(a_1, a_2);
}
