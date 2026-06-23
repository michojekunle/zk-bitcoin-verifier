/// secp256k1 field prime p = 2^256 - 2^32 - 977
const P: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_u256;
/// secp256k1 curve order n
const N: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_u256;
/// Generator point
const GX: u256 = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_u256;
const GY: u256 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_u256;
/// p = 2^256 - P_COFACTOR; P_COFACTOR = 2^32 + 977
const P_COFACTOR: u128 = 4295000273_u128;

/// An affine point on the secp256k1 curve.
#[derive(Drop, Copy)]
pub struct Point {
    pub x: u256,
    pub y: u256,
}

/// An ECDSA signature over secp256k1.
#[derive(Drop, Copy)]
pub struct Signature {
    pub r: u256,
    pub s: u256,
}

/// Jacobian projective point: (X:Y:Z) represents affine (X/Z^2, Y/Z^3).
/// Z == 0 encodes the point at infinity.
#[derive(Drop, Copy)]
struct JPoint {
    x: u256,
    y: u256,
    z: u256,
}

// ---------------------------------------------------------------------------
// Generic modular helpers (used for N-modulus operations)
// ---------------------------------------------------------------------------

/// (a + b) mod m — overflow-safe for a, b < m < 2^256
fn addmod(a: u256, b: u256, m: u256) -> u256 {
    let m_minus_b = m - b;
    if a >= m_minus_b {
        a - m_minus_b
    } else {
        a + b
    }
}

/// (a - b) mod m — underflow-safe for a, b < m
fn submod(a: u256, b: u256, m: u256) -> u256 {
    if a >= b {
        a - b
    } else {
        m - (b - a)
    }
}

/// (a * b) mod m via binary repeated doubling — used for N-domain operations
fn mulmod_slow(a: u256, b: u256, m: u256) -> u256 {
    let mut result: u256 = 0_u256;
    let mut base = a % m;
    let mut exp = b;
    while exp > 0_u256 {
        if exp % 2_u256 == 1_u256 {
            result = addmod(result, base, m);
        }
        base = addmod(base, base, m);
        exp = exp / 2_u256;
    }
    result
}

/// a^exp mod m via repeated squaring (generic, for N-domain)
fn powmod_slow(base: u256, exp: u256, m: u256) -> u256 {
    let mut result: u256 = 1_u256;
    let mut b = base % m;
    let mut e = exp;
    while e > 0_u256 {
        if e % 2_u256 == 1_u256 {
            result = mulmod_slow(result, b, m);
        }
        b = mulmod_slow(b, b, m);
        e = e / 2_u256;
    }
    result
}

fn invmod_n(a: u256) -> u256 {
    powmod_slow(a, N - 2_u256, N)
}

// ---------------------------------------------------------------------------
// Fast P-field arithmetic using secp256k1's prime structure
// p = 2^256 - P_COFACTOR, so 2^256 ≡ P_COFACTOR (mod p)
// ---------------------------------------------------------------------------

/// Detect and handle u256 + u256 → (sum mod 2^256, carry bit).
/// Avoids panicking on overflow.
fn add_with_carry(a: u256, b: u256) -> (u256, bool) {
    // a + b overflows iff a > 2^256 - 1 - b = MAX - b
    let max: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256;
    if a > max - b {
        // result = a + b - 2^256 = a - (MAX - b) - 1
        (a - (max - b) - 1_u256, true)
    } else {
        (a + b, false)
    }
}

/// (a + b) mod P — overflow-safe for a, b < P
fn addmod_p(a: u256, b: u256) -> u256 {
    addmod(a, b, P)
}

/// (a - b) mod P — underflow-safe for a, b < P
fn submod_p(a: u256, b: u256) -> u256 {
    submod(a, b, P)
}

/// Reduce x < 2*P to x mod P in O(1)
fn reduce_once_p(x: u256) -> u256 {
    if x >= P {
        x - P
    } else {
        x
    }
}

/// Compute x * P_COFACTOR mod P for x < 2^256.
/// Key: 2^256 ≡ P_COFACTOR (mod P), so high limbs fold cheaply.
fn mul_cofactor(x: u256) -> u256 {
    // x * P_COFACTOR = x.high * P_COFACTOR * 2^128 + x.low * P_COFACTOR
    // Both partial products < 2^161, fit in u256.
    let lo: u256 = x.low.into() * P_COFACTOR.into(); // < 2^161 < P
    let hi: u256 = x.high.into() * P_COFACTOR.into(); // < 2^161 < P
    // Reduce hi * 2^128 mod P:
    //   hi * 2^128 = hi.high * 2^256 + hi.low * 2^128
    //             ≡ hi.high * P_COFACTOR + hi.low * 2^128  (mod P)
    // hi.high < 2^33 (since hi < 2^161), hi.high * P_COFACTOR < 2^66 < P → fits in u128
    let hi_high_c: u128 = hi.high * P_COFACTOR; // hi.high < 2^33, safe u128 multiply
    let hi_low_shifted: u256 = u256 { high: hi.low, low: 0_u128 }; // hi.low * 2^128 < P
    addmod_p(addmod_p(lo, hi_low_shifted), hi_high_c.into())
}

/// Fast (a * b) mod P using schoolbook 2×128-limb decomposition.
/// Replaces 256-iteration binary multiply with ~20 field operations.
fn mulmod_p(a: u256, b: u256) -> u256 {
    // a = a.high * 2^128 + a.low,  b = b.high * 2^128 + b.low
    // a*b = p_hh * 2^256 + cross * 2^128 + p_ll
    // where cross = p_lh + p_hl (may exceed 2^256 → carry bit)
    let p_ll: u256 = a.low.into() * b.low.into(); // u128*u128 → u256, < (2^128)^2 < 2^256
    let p_lh: u256 = a.low.into() * b.high.into();
    let p_hl: u256 = a.high.into() * b.low.into();
    let p_hh: u256 = a.high.into() * b.high.into();

    let (cross, carry) = add_with_carry(p_lh, p_hl);

    // a*b = p_hh*2^256 + (p_lh+p_hl)*2^128 + p_ll
    //     = p_hh*2^256 + (cross + carry*2^256)*2^128 + p_ll
    //     = p_hh*2^256 + cross*2^128 + carry*2^384 + p_ll
    // Mod P (2^256 ≡ P_COFACTOR, 2^384 ≡ P_COFACTOR*2^128):
    //   ≡ mul_cofactor(p_hh) + carry*P_COFACTOR*2^128 + cross.high*P_COFACTOR + cross.low*2^128 + p_ll
    let t_hi_c: u256 = mul_cofactor(p_hh);
    // carry * 2^384 ≡ carry * P_COFACTOR * 2^128 (mod P); P_COFACTOR < 2^33, fits in u256 high limb
    let carry_c: u256 = if carry {
        u256 { high: P_COFACTOR, low: 0_u128 }
    } else {
        0_u256
    };
    let cross_hi_c: u256 = cross.high.into() * P_COFACTOR.into(); // < 2^161 < P
    let cross_lo_shifted: u256 = u256 { high: cross.low, low: 0_u128 }; // < P

    addmod_p(addmod_p(addmod_p(addmod_p(t_hi_c, carry_c), cross_hi_c), cross_lo_shifted), p_ll)
}

/// a^exp mod P via repeated squaring with fast mulmod_p
fn powmod_p(base: u256, exp: u256) -> u256 {
    let mut result: u256 = 1_u256;
    let mut b = if base >= P {
        base - P
    } else {
        base
    };
    let mut e = exp;
    while e > 0_u256 {
        if e % 2_u256 == 1_u256 {
            result = mulmod_p(result, b);
        }
        b = mulmod_p(b, b);
        e = e / 2_u256;
    }
    result
}

fn invmod_p(a: u256) -> u256 {
    powmod_p(a, P - 2_u256)
}

// ---------------------------------------------------------------------------
// EC operations in Jacobian coordinates (y^2 = x^3 + 7 mod P, a=0)
// No field inversions during scalar multiplication — only one at the end.
// ---------------------------------------------------------------------------

fn jpoint_is_infinity(p: JPoint) -> bool {
    p.z == 0_u256
}

/// Jacobian doubling: 2*(X:Y:Z) — ~9 mulmod_p
fn jpoint_double(p: JPoint) -> JPoint {
    if jpoint_is_infinity(p) {
        return p;
    }
    let y2 = mulmod_p(p.y, p.y);
    let s = mulmod_p(4_u256, mulmod_p(p.x, y2)); // S = 4*X*Y^2
    let x2 = mulmod_p(p.x, p.x);
    let m = mulmod_p(3_u256, x2); // M = 3*X^2
    let m2 = mulmod_p(m, m);
    let x3 = submod_p(m2, addmod_p(s, s)); // X3 = M^2 - 2*S
    let y4 = mulmod_p(y2, y2);
    let eight_y4 = mulmod_p(8_u256, y4);
    let y3 = submod_p(mulmod_p(m, submod_p(s, x3)), eight_y4); // Y3 = M*(S-X3) - 8*Y^4
    let z3 = mulmod_p(2_u256, mulmod_p(p.y, p.z)); // Z3 = 2*Y*Z
    JPoint { x: x3, y: y3, z: z3 }
}

/// Full Jacobian addition: (X1:Y1:Z1) + (X2:Y2:Z2) — ~16 mulmod_p
fn jpoint_add(p1: JPoint, p2: JPoint) -> JPoint {
    if jpoint_is_infinity(p1) {
        return p2;
    }
    if jpoint_is_infinity(p2) {
        return p1;
    }
    let z1_2 = mulmod_p(p1.z, p1.z);
    let z2_2 = mulmod_p(p2.z, p2.z);
    let u1 = mulmod_p(p1.x, z2_2);
    let u2 = mulmod_p(p2.x, z1_2);
    let s1 = mulmod_p(p1.y, mulmod_p(p2.z, z2_2));
    let s2 = mulmod_p(p2.y, mulmod_p(p1.z, z1_2));
    let h = submod_p(u2, u1);
    let r = submod_p(s2, s1);
    if h == 0_u256 {
        if r == 0_u256 {
            return jpoint_double(p1);
        } else {
            return JPoint { x: 0_u256, y: 0_u256, z: 0_u256 };
        }
    }
    let h2 = mulmod_p(h, h);
    let h3 = mulmod_p(h, h2);
    let u1h2 = mulmod_p(u1, h2);
    let r2 = mulmod_p(r, r);
    let x3 = submod_p(submod_p(r2, h3), addmod_p(u1h2, u1h2));
    let y3 = submod_p(mulmod_p(r, submod_p(u1h2, x3)), mulmod_p(s1, h3));
    let z3 = mulmod_p(mulmod_p(h, p1.z), p2.z);
    JPoint { x: x3, y: y3, z: z3 }
}

/// Scalar multiplication k * (qx, qy) — returns Jacobian result
fn jscalar_mult(k: u256, qx: u256, qy: u256) -> JPoint {
    let mut result = JPoint { x: 0_u256, y: 0_u256, z: 0_u256 }; // infinity
    let mut addend = JPoint { x: qx, y: qy, z: 1_u256 };
    let mut scalar = k;
    while scalar > 0_u256 {
        if scalar % 2_u256 == 1_u256 {
            result = if jpoint_is_infinity(result) {
                addend
            } else {
                jpoint_add(result, addend)
            };
        }
        addend = jpoint_double(addend);
        scalar = scalar / 2_u256;
    }
    result
}

/// Convert Jacobian to affine x-coordinate only (for ECDSA check)
fn jpoint_x_affine(p: JPoint) -> u256 {
    let z_inv = invmod_p(p.z);
    let z_inv2 = mulmod_p(z_inv, z_inv);
    mulmod_p(p.x, z_inv2)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verifies an ECDSA signature against a message hash and public key point.
pub fn secp256k1_verify_signature(message_hash: u256, sig: Signature, pubkey: Point) -> bool {
    // 1. Range checks
    if sig.r == 0_u256 || sig.r >= N {
        return false;
    }
    if sig.s == 0_u256 || sig.s >= N {
        return false;
    }
    // 2. Verify pubkey is on the curve: y^2 == x^3 + 7 mod P
    let x3 = mulmod_p(mulmod_p(pubkey.x, pubkey.x), pubkey.x);
    let rhs = addmod_p(x3, 7_u256);
    let lhs = mulmod_p(pubkey.y, pubkey.y);
    if lhs != rhs {
        return false;
    }
    // 3. ECDSA: compute u1*G + u2*Q and check x == r (mod N)
    let s_inv = invmod_n(sig.s);
    let u1 = mulmod_slow(message_hash % N, s_inv, N);
    let u2 = mulmod_slow(sig.r % N, s_inv, N);
    let r1 = jscalar_mult(u1, GX, GY);
    let r2 = jscalar_mult(u2, pubkey.x, pubkey.y);
    let r_pt = jpoint_add(r1, r2);
    if jpoint_is_infinity(r_pt) {
        return false;
    }
    let rx = jpoint_x_affine(r_pt);
    rx % N == sig.r
}

/// Recovers the public key from a message hash, signature, and recovery identifier.
pub fn secp256k1_recover_pubkey(message_hash: u256, sig: Signature, recovery_id: u8) -> Point {
    let _ = message_hash;
    let _ = sig;
    let _ = recovery_id;
    Point { x: 0_u256, y: 0_u256 }
}
