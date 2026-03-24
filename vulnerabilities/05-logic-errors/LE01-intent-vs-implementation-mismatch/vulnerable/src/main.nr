// LE01 -- Intent vs Implementation Mismatch
// ============================================================
// Vulnerability ID : LE01
// Category         : Logic Error
// Severity         : High
// Difficulty       : Hard
// Hint Level       : 3
// ============================================================
//
// Scenario:
//   An NFT marketplace. To list an NFT for sale, the owner must prove
//   they OWN it. The marketplace verifies an ownership proof before
//   allowing a listing.
//
//   Ownership is stored as: owner_commitment = pedersen_hash([owner_key, token_id])
//   (registered on-chain when the NFT was minted)
//
// Spec:
//   Prove: you know owner_key such that
//     pedersen_hash([owner_key, token_id]) == owner_commitment
//   This binds the owner_key to the specific token.
//
// Bug:
//   The circuit LOOKS like it checks ownership but actually only verifies
//   knowledge of metadata (which is PUBLIC). The owner_key is never used
//   in any constraint -- it's a dead variable.
//
//   Anyone who knows the public metadata can forge an ownership proof.

fn main(
    token_id: pub Field,         // Public:  which NFT
    metadata_hash: pub Field,    // Public:  hash of NFT metadata (publicly available!)
    owner_commitment: pub Field, // Public:  owner_commitment stored on-chain
    owner_key: Field             // Private: owner's secret key (NEVER USED!)
) {
    // Developer thought they were verifying ownership...
    // But this only checks that token_id hashes to metadata_hash.
    // metadata_hash is PUBLIC on-chain -- anyone can see it!
    let computed = std::hash::pedersen_hash([token_id]);
    assert(computed == metadata_hash);

    // !!BUG: owner_key is declared but NEVER appears in any assert!!
    //
    // The intent was:
    //   assert(pedersen_hash([owner_key, token_id]) == owner_commitment)
    //
    // What the circuit actually proves:
    //   "You know token_id such that hash(token_id) == metadata_hash"
    //   Since metadata_hash is publicly available, ANYONE can generate this proof.
    //
    // owner_key and owner_commitment are completely unconstrained relative to each other.
    // A non-owner can list Alice's NFT by providing any owner_key value.
    //
    // MISSING: assert(pedersen_hash([owner_key, token_id]) == owner_commitment);
    assert(owner_commitment != 0); // This check is meaningless for ownership
}
