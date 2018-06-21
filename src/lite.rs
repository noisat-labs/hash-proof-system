use rand::{ Rng, CryptoRng };
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{ RistrettoPoint, CompressedRistretto };
use ::{ SmoothProjectiveHash, PriveHash, PublicHash, Language as LanguageTrait };


pub struct LiteSPHF {
    language: &'static Language
}

pub struct PriveKey {
    group: &'static Language,
    a: Scalar,
    b: Scalar
}

pub struct PublicKey {
    hp: RistrettoPoint
}

pub struct Language {
    pub g: RistrettoPoint,
    pub h: Scalar
}

pub struct Commitment {
    x: RistrettoPoint,
    y: RistrettoPoint
}

impl SmoothProjectiveHash for LiteSPHF {
    type Output = CompressedRistretto;
    type Language = Language;
    type PriveKey = PriveKey;

    fn new(language: &'static Language) -> Self {
        LiteSPHF { language }
    }

    fn keygen<R: Rng + CryptoRng>(&self, mut rng: R) -> Self::PriveKey {
        let group = self.language;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        PriveKey { group, a, b }
    }
}

impl PriveHash<Language, CompressedRistretto> for PriveKey {
    type PublicKey = PublicKey;

    fn proj_keygen(&self) -> Self::PublicKey {
        let &PriveKey { group: Language { g, h }, a, b } = self;

        let hp = g * a + g * (h * b);

        PublicKey { hp }
    }

    fn hash(&self, target: &<Language as LanguageTrait>::Element) -> CompressedRistretto {
        let &PriveKey { a, b, .. } = self;
        let Commitment { x, y } = target;

        ((x * a) + (y * b)).compress()
    }
}

impl PublicHash<Language, CompressedRistretto> for PublicKey {
    fn proj_hash(
        &self,
        witness: &<Language as LanguageTrait>::Witness,
        _target: &<Language as LanguageTrait>::Element
    ) -> CompressedRistretto {
        let PublicKey { hp } = self;

        (hp * witness).compress()
    }
}

impl LanguageTrait for Language {
    type Input = Scalar;
    type Witness = Scalar;
    type Element = Commitment;

    fn commitment(&self, witness: &Self::Witness, input: &Self::Input) -> Self::Element {
        let &Language { g, h } = self;

        let x = g * witness;
        let y = g * (h * input);

        Commitment { x, y }
    }
}


#[test]
fn test_sphf() {
    use rand::OsRng;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let mut osrng = OsRng::new().unwrap();
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = Scalar::random(&mut osrng);
    let language = Box::new(Language { g, h });
    let language = Box::leak(language);

//    let w = Scalar::random(&mut osrng);
    let w = Scalar::from_u64(0x9527);
    let input = Scalar::from_u64(0x9527);

    let sphf = LiteSPHF::new(language);
    let sk = sphf.keygen(&mut osrng);
    let pk = sk.proj_keygen();

    let target = language.commitment(&w, &input);
    let o1 = sk.hash(&target);
    let o2 = pk.proj_hash(&w, &target);

    assert_eq!(o1, o2);
}
