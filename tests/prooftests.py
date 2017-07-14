from emmy.proofs.cspaillierproof import CSPaillierProof

proof = CSPaillierProof()
m = 2349090
L = 834848
proof.prove(m, L)
print("--------")
