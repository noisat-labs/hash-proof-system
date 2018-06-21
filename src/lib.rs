extern crate rand;
extern crate curve25519_dalek;

pub mod lite;

use rand::{ Rng, CryptoRng };


pub trait SmoothProjectiveHash {
    type Output;
    type Language: Language;
    type PriveKey: PriveHash<Self::Language, Self::Output>;

    fn new(language: &'static Self::Language) -> Self;
    fn keygen<R: Rng + CryptoRng>(&self, rng: R) -> Self::PriveKey;
}

pub trait PriveHash<L, O>
    where L: Language
{
    type PublicKey: PublicHash<L, O>;

    fn proj_keygen(&self) -> Self::PublicKey;
    fn hash(&self, target: &L::Element) -> O;
}

pub trait PublicHash<L, O>
    where L: Language
{
    fn proj_hash(&self, witness: &L::Witness, target: &L::Element) -> O;
}

pub trait Language {
    type Input;
    type Witness;
    type Element;

    fn commitment(&self, witness: &Self::Witness, input: &Self::Input) -> Self::Element;
}
