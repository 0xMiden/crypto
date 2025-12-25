#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// Allow cfg warnings for optional features from fn-dsa that aren't in this codebase
#![allow(unexpected_cfgs)]
// Allow dead code for utility functions that may be used in the future
#![allow(dead_code)]
// Allow excessive precision in float constants (needed for FLR accuracy)
#![allow(clippy::excessive_precision)]
// Allow fn-dsa coding style preferences
#![allow(clippy::needless_range_loop)]
#![allow(clippy::needless_return)]
#![allow(clippy::transmute_undefined_repr)]
#![allow(clippy::missing_transmute_annotations)]

// ========================================================================
// Floating-point operations: native
// ========================================================================

// This file implements the FLR type for IEEE-754:2008 operations, with
// the requirements listed in flr.rs (in particular, there is no support
// for denormals, infinites or NaNs). The implementation uses the native
// 'f64' type; it should be used only for architectures for which the
// hardware can be assumed to operate in a sufficiently constant-time way.

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
#[allow(clippy::upper_case_acronyms)] // FLR is the standard name from fn-dsa
pub(crate) struct FLR(f64);

impl FLR {
    pub(crate) const ZERO: Self = Self(0.0);
    pub(crate) const NZERO: Self = Self(-0.0);
    pub(crate) const ONE: Self = Self(1.0);

    // Hardcoded powers of 2 for 2^(+127) to 2^(-128). This is used to
    // implement some operations where the exponent is not secret.
    // Values here were computed with 140 bits of precision, which is
    // overkill (such powers of 2 are exact in IEEE-754 'binary64'
    // format).
    pub(crate) const INV_POW2: [f64; 256] = [
        1.7014118346046923173168730371588410572800e38,
        8.5070591730234615865843651857942052864000e37,
        4.2535295865117307932921825928971026432000e37,
        2.1267647932558653966460912964485513216000e37,
        1.0633823966279326983230456482242756608000e37,
        5.3169119831396634916152282411213783040000e36,
        2.6584559915698317458076141205606891520000e36,
        1.3292279957849158729038070602803445760000e36,
        6.6461399789245793645190353014017228800000e35,
        3.3230699894622896822595176507008614400000e35,
        1.6615349947311448411297588253504307200000e35,
        8.3076749736557242056487941267521536000000e34,
        4.1538374868278621028243970633760768000000e34,
        2.0769187434139310514121985316880384000000e34,
        1.0384593717069655257060992658440192000000e34,
        5.1922968585348276285304963292200960000000e33,
        2.5961484292674138142652481646100480000000e33,
        1.2980742146337069071326240823050240000000e33,
        6.4903710731685345356631204115251200000000e32,
        3.2451855365842672678315602057625600000000e32,
        1.6225927682921336339157801028812800000000e32,
        8.1129638414606681695789005144064000000000e31,
        4.0564819207303340847894502572032000000000e31,
        2.0282409603651670423947251286016000000000e31,
        1.0141204801825835211973625643008000000000e31,
        5.0706024009129176059868128215040000000000e30,
        2.5353012004564588029934064107520000000000e30,
        1.2676506002282294014967032053760000000000e30,
        6.3382530011411470074835160268800000000000e29,
        3.1691265005705735037417580134400000000000e29,
        1.5845632502852867518708790067200000000000e29,
        7.9228162514264337593543950336000000000000e28,
        3.9614081257132168796771975168000000000000e28,
        1.9807040628566084398385987584000000000000e28,
        9.9035203142830421991929937920000000000000e27,
        4.9517601571415210995964968960000000000000e27,
        2.4758800785707605497982484480000000000000e27,
        1.2379400392853802748991242240000000000000e27,
        6.1897001964269013744956211200000000000000e26,
        3.0948500982134506872478105600000000000000e26,
        1.5474250491067253436239052800000000000000e26,
        7.7371252455336267181195264000000000000000e25,
        3.8685626227668133590597632000000000000000e25,
        1.9342813113834066795298816000000000000000e25,
        9.6714065569170333976494080000000000000000e24,
        4.8357032784585166988247040000000000000000e24,
        2.4178516392292583494123520000000000000000e24,
        1.2089258196146291747061760000000000000000e24,
        6.0446290980731458735308800000000000000000e23,
        3.0223145490365729367654400000000000000000e23,
        1.5111572745182864683827200000000000000000e23,
        7.5557863725914323419136000000000000000000e22,
        3.7778931862957161709568000000000000000000e22,
        1.8889465931478580854784000000000000000000e22,
        9.4447329657392904273920000000000000000000e21,
        4.7223664828696452136960000000000000000000e21,
        2.3611832414348226068480000000000000000000e21,
        1.1805916207174113034240000000000000000000e21,
        5.9029581035870565171200000000000000000000e20,
        2.9514790517935282585600000000000000000000e20,
        1.4757395258967641292800000000000000000000e20,
        7.3786976294838206464000000000000000000000e19,
        3.6893488147419103232000000000000000000000e19,
        1.8446744073709551616000000000000000000000e19,
        9.2233720368547758080000000000000000000000e18,
        4.6116860184273879040000000000000000000000e18,
        2.3058430092136939520000000000000000000000e18,
        1.1529215046068469760000000000000000000000e18,
        5.7646075230342348800000000000000000000000e17,
        2.8823037615171174400000000000000000000000e17,
        1.4411518807585587200000000000000000000000e17,
        7.2057594037927936000000000000000000000000e16,
        3.6028797018963968000000000000000000000000e16,
        1.8014398509481984000000000000000000000000e16,
        9.0071992547409920000000000000000000000000e15,
        4.5035996273704960000000000000000000000000e15,
        2.2517998136852480000000000000000000000000e15,
        1.1258999068426240000000000000000000000000e15,
        5.6294995342131200000000000000000000000000e14,
        2.8147497671065600000000000000000000000000e14,
        1.4073748835532800000000000000000000000000e14,
        7.0368744177664000000000000000000000000000e13,
        3.5184372088832000000000000000000000000000e13,
        1.7592186044416000000000000000000000000000e13,
        8.7960930222080000000000000000000000000000e12,
        4.3980465111040000000000000000000000000000e12,
        2.1990232555520000000000000000000000000000e12,
        1.0995116277760000000000000000000000000000e12,
        5.4975581388800000000000000000000000000000e11,
        2.7487790694400000000000000000000000000000e11,
        1.3743895347200000000000000000000000000000e11,
        6.8719476736000000000000000000000000000000e10,
        3.4359738368000000000000000000000000000000e10,
        1.7179869184000000000000000000000000000000e10,
        8.5899345920000000000000000000000000000000e9,
        4.2949672960000000000000000000000000000000e9,
        2.1474836480000000000000000000000000000000e9,
        1.0737418240000000000000000000000000000000e9,
        5.3687091200000000000000000000000000000000e8,
        2.6843545600000000000000000000000000000000e8,
        1.3421772800000000000000000000000000000000e8,
        6.7108864000000000000000000000000000000000e7,
        3.3554432000000000000000000000000000000000e7,
        1.6777216000000000000000000000000000000000e7,
        8.3886080000000000000000000000000000000000e6,
        4.1943040000000000000000000000000000000000e6,
        2.0971520000000000000000000000000000000000e6,
        1.0485760000000000000000000000000000000000e6,
        524288.00000000000000000000000000000000000,
        262144.00000000000000000000000000000000000,
        131072.00000000000000000000000000000000000,
        65536.000000000000000000000000000000000000,
        32768.000000000000000000000000000000000000,
        16384.000000000000000000000000000000000000,
        8192.0000000000000000000000000000000000000,
        4096.0000000000000000000000000000000000000,
        2048.0000000000000000000000000000000000000,
        1024.0000000000000000000000000000000000000,
        512.00000000000000000000000000000000000000,
        256.00000000000000000000000000000000000000,
        128.00000000000000000000000000000000000000,
        64.000000000000000000000000000000000000000,
        32.000000000000000000000000000000000000000,
        16.000000000000000000000000000000000000000,
        8.0000000000000000000000000000000000000000,
        4.0000000000000000000000000000000000000000,
        2.0000000000000000000000000000000000000000,
        1.0000000000000000000000000000000000000000,
        0.50000000000000000000000000000000000000000,
        0.25000000000000000000000000000000000000000,
        0.12500000000000000000000000000000000000000,
        0.062500000000000000000000000000000000000000,
        0.031250000000000000000000000000000000000000,
        0.015625000000000000000000000000000000000000,
        0.0078125000000000000000000000000000000000000,
        0.0039062500000000000000000000000000000000000,
        0.0019531250000000000000000000000000000000000,
        0.00097656250000000000000000000000000000000000,
        0.00048828125000000000000000000000000000000000,
        0.00024414062500000000000000000000000000000000,
        0.00012207031250000000000000000000000000000000,
        0.000061035156250000000000000000000000000000000,
        0.000030517578125000000000000000000000000000000,
        0.000015258789062500000000000000000000000000000,
        7.6293945312500000000000000000000000000000e-6,
        3.8146972656250000000000000000000000000000e-6,
        1.9073486328125000000000000000000000000000e-6,
        9.5367431640625000000000000000000000000000e-7,
        4.7683715820312500000000000000000000000000e-7,
        2.3841857910156250000000000000000000000000e-7,
        1.1920928955078125000000000000000000000000e-7,
        5.9604644775390625000000000000000000000000e-8,
        2.9802322387695312500000000000000000000000e-8,
        1.4901161193847656250000000000000000000000e-8,
        7.4505805969238281250000000000000000000000e-9,
        3.7252902984619140625000000000000000000000e-9,
        1.8626451492309570312500000000000000000000e-9,
        9.3132257461547851562500000000000000000000e-10,
        4.6566128730773925781250000000000000000000e-10,
        2.3283064365386962890625000000000000000000e-10,
        1.1641532182693481445312500000000000000000e-10,
        5.8207660913467407226562500000000000000000e-11,
        2.9103830456733703613281250000000000000000e-11,
        1.4551915228366851806640625000000000000000e-11,
        7.2759576141834259033203125000000000000000e-12,
        3.6379788070917129516601562500000000000000e-12,
        1.8189894035458564758300781250000000000000e-12,
        9.0949470177292823791503906250000000000000e-13,
        4.5474735088646411895751953125000000000000e-13,
        2.2737367544323205947875976562500000000000e-13,
        1.1368683772161602973937988281250000000000e-13,
        5.6843418860808014869689941406250000000000e-14,
        2.8421709430404007434844970703125000000000e-14,
        1.4210854715202003717422485351562500000000e-14,
        7.1054273576010018587112426757812500000000e-15,
        3.5527136788005009293556213378906250000000e-15,
        1.7763568394002504646778106689453125000000e-15,
        8.8817841970012523233890533447265625000000e-16,
        4.4408920985006261616945266723632812500000e-16,
        2.2204460492503130808472633361816406250000e-16,
        1.1102230246251565404236316680908203125000e-16,
        5.5511151231257827021181583404541015625000e-17,
        2.7755575615628913510590791702270507812500e-17,
        1.3877787807814456755295395851135253906250e-17,
        6.9388939039072283776476979255676269531250e-18,
        3.4694469519536141888238489627838134765625e-18,
        1.7347234759768070944119244813919067382812e-18,
        8.6736173798840354720596224069595336914062e-19,
        4.3368086899420177360298112034797668457031e-19,
        2.1684043449710088680149056017398834228516e-19,
        1.0842021724855044340074528008699417114258e-19,
        5.4210108624275221700372640043497085571289e-20,
        2.7105054312137610850186320021748542785645e-20,
        1.3552527156068805425093160010874271392822e-20,
        6.7762635780344027125465800054371356964111e-21,
        3.3881317890172013562732900027185678482056e-21,
        1.6940658945086006781366450013592839241028e-21,
        8.4703294725430033906832250067964196205139e-22,
        4.2351647362715016953416125033982098102570e-22,
        2.1175823681357508476708062516991049051285e-22,
        1.0587911840678754238354031258495524525642e-22,
        5.2939559203393771191770156292477622628212e-23,
        2.6469779601696885595885078146238811314106e-23,
        1.3234889800848442797942539073119405657053e-23,
        6.6174449004242213989712695365597028285265e-24,
        3.3087224502121106994856347682798514142632e-24,
        1.6543612251060553497428173841399257071316e-24,
        8.2718061255302767487140869206996285356581e-25,
        4.1359030627651383743570434603498142678291e-25,
        2.0679515313825691871785217301749071339145e-25,
        1.0339757656912845935892608650874535669573e-25,
        5.1698788284564229679463043254372678347863e-26,
        2.5849394142282114839731521627186339173932e-26,
        1.2924697071141057419865760813593169586966e-26,
        6.4623485355705287099328804067965847934829e-27,
        3.2311742677852643549664402033982923967415e-27,
        1.6155871338926321774832201016991461983707e-27,
        8.0779356694631608874161005084957309918536e-28,
        4.0389678347315804437080502542478654959268e-28,
        2.0194839173657902218540251271239327479634e-28,
        1.0097419586828951109270125635619663739817e-28,
        5.0487097934144755546350628178098318699085e-29,
        2.5243548967072377773175314089049159349543e-29,
        1.2621774483536188886587657044524579674771e-29,
        6.3108872417680944432938285222622898373857e-30,
        3.1554436208840472216469142611311449186928e-30,
        1.5777218104420236108234571305655724593464e-30,
        7.8886090522101180541172856528278622967321e-31,
        3.9443045261050590270586428264139311483660e-31,
        1.9721522630525295135293214132069655741830e-31,
        9.8607613152626475676466070660348278709151e-32,
        4.9303806576313237838233035330174139354575e-32,
        2.4651903288156618919116517665087069677288e-32,
        1.2325951644078309459558258832543534838644e-32,
        6.1629758220391547297791294162717674193219e-33,
        3.0814879110195773648895647081358837096610e-33,
        1.5407439555097886824447823540679418548305e-33,
        7.7037197775489434122239117703397092741524e-34,
        3.8518598887744717061119558851698546370762e-34,
        1.9259299443872358530559779425849273185381e-34,
        9.6296497219361792652798897129246365926905e-35,
        4.8148248609680896326399448564623182963453e-35,
        2.4074124304840448163199724282311591481726e-35,
        1.2037062152420224081599862141155795740863e-35,
        6.0185310762101120407999310705778978704316e-36,
        3.0092655381050560203999655352889489352158e-36,
        1.5046327690525280101999827676444744676079e-36,
        7.5231638452626400509999138382223723380395e-37,
        3.7615819226313200254999569191111861690197e-37,
        1.8807909613156600127499784595555930845099e-37,
        9.4039548065783000637498922977779654225493e-38,
        4.7019774032891500318749461488889827112747e-38,
        2.3509887016445750159374730744444913556373e-38,
        1.1754943508222875079687365372222456778187e-38,
        5.8774717541114375398436826861112283890933e-39,
        2.9387358770557187699218413430556141945467e-39,
    ];

    #[inline(always)]
    pub(crate) const fn from_i64(j: i64) -> Self {
        Self(j as f64)
    }

    #[inline(always)]
    pub(crate) const fn from_i32(j: i32) -> Self {
        Self(j as f64)
    }

    // Specialized code (e.g. AVX2 on x86_64) may access the inner f64
    // value directly.
    #[allow(dead_code)]
    #[inline(always)]
    pub(crate) const fn to_f64(self) -> f64 {
        self.0
    }

    // Create FLR from f64 value
    #[inline(always)]
    pub(crate) const fn from_f64(x: f64) -> Self {
        Self(x)
    }

    #[inline(always)]
    pub(crate) const fn scaled(j: i64, sc: i32) -> Self {
        // Since from_i32() and from_i64() use direct integer-to-float
        // conversions, this function will be called only for evaluating
        // compile-time constants. However, there are limitations to what
        // can be done in const functions; in particular, loops are not
        // allowed. We could use recursion, but it seems simpler to
        // hardcode some scaling factors since all the 'sc' values in
        // practice will be in a limited range.
        //
        // Largest range for sc is [+127, -128].
        Self((j as f64) * Self::INV_POW2[(127 - sc) as usize])
    }

    // Encode to 8 bytes (IEEE-754 binary64 format, little-endian).
    // This is meant for tests only; this function does not need to be
    // constant-time.
    #[allow(dead_code)]
    pub(crate) fn encode(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    // Decode from 8 bytes (IEEE-754 binary64 format, little-endian).
    // This is meant for tests only; this function does not need to be
    // constant-time.
    #[allow(dead_code)]
    pub(crate) fn decode(src: &[u8]) -> Option<Self> {
        match src.len() {
            8 => Some(Self(f64::from_le_bytes(*<&[u8; 8]>::try_from(src).unwrap()))),
            _ => None,
        }
    }

    // Return self / 2.
    #[inline(always)]
    pub(crate) fn half(self) -> Self {
        Self(self.0 * 0.5)
    }

    // Return self * 2.
    // (used in some tests)
    #[allow(dead_code)]
    #[inline(always)]
    pub(crate) fn double(self) -> Self {
        Self(self.0 * 2.0)
    }

    // Multiply this value by 2^63.
    #[inline(always)]
    pub(crate) fn mul2p63(self) -> Self {
        Self(self.0 * 9223372036854775808.0)
    }

    // Divide all values in the provided slice with 2^e, for e in the
    // 1 to 9 range (inclusive). The value of e is not considered secret.
    // This is a helper function used in the implementation of the FFT
    // and included in the FLR API because different implementations might
    // do it very differently.
    #[allow(dead_code)]
    pub(crate) fn slice_div2e(f: &mut [FLR], e: u32) {
        let ee = Self::INV_POW2[(e + 127) as usize];
        for i in 0..f.len() {
            f[i] = Self(f[i].0 * ee);
        }
    }

    #[inline]
    pub(crate) fn rint(self) -> i64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use core::arch::x86_64::*;

            // On x86_64, we have SSE2, and there is an opcode that
            // does exactly what we need. The conversion from f64 to
            // __m128d is really a no-op, since f64 is itself backed
            // by SSE2.
            return _mm_cvtsd_si64(_mm_set_sd(self.0));
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
        unsafe {
            use core::arch::aarch64::*;

            // On aarch64, we use the NEON opcodes.
            return vcvtnd_s64_f64(self.0);
        }

        #[cfg(target_arch = "riscv64")]
        unsafe {
            use core::arch::asm;
            let mut d: i64;
            asm!("fcvt.l.d {d}, {a}, rne", a = in(freg) self.0, d = out(reg) d);
            return d;
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            // Suppose that x >= 0. If x >= 2^52, then it is already an
            // integer. Otherwise, computing x + 2^52 will yield a value
            // that is rounded to the nearest integer with exactly the right
            // rules (roundTiesToEven). For constant-time processing we must
            // do the computation for both x >= 0 and x < 0 cases, then
            // select the right output.
            let x = self.0;
            let sx = (x - 1.0) as i64;
            let tx = x as i64;
            let rp = ((x + 4503599627370496.0) as i64) - 4503599627370496;
            let rn = ((x - 4503599627370496.0) as i64) + 4503599627370496;

            // Assuming that |x| < 2^52:
            // If sx >= 0, then the result is rp; otherwise, result is rn.
            // We use the fact that when x is close to 0 (|x| <= 0.25), then
            // both rp and rn are correct (they are both zero); but if x is
            // not close to 0, then trunc(x - 1.0) (i.e. sx) has the correct
            // sign. Thus, we use rp if sx >= 0, rn otherwise.
            let z = rp ^ ((sx >> 63) & (rp ^ rn));

            // If the twelve upper bits of tx are not all-zeros or all-ones,
            // then tx >= 2^52 or tx < -2^52, and is exact; in that case,
            // we replace z with tx.
            let hi = (tx as u64).wrapping_add(1u64 << 52) >> 52;
            let m = (hi.wrapping_sub(2) as i64) >> 16;
            return tx ^ (m & (z ^ tx));
        }
    }

    #[inline(always)]
    pub(crate) fn floor(self) -> i64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use core::arch::x86_64::*;
            let x = self.0;
            let r = x as i64;
            let t = _mm_comilt_sd(_mm_set_sd(x), _mm_cvtsi64x_sd(_mm_setzero_pd(), r));
            return r - (t as i64);
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
        unsafe {
            use core::arch::aarch64::*;
            return vcvtmd_s64_f64(self.0);
        }

        #[cfg(target_arch = "riscv64")]
        unsafe {
            use core::arch::asm;
            let mut d: i64;
            asm!("fcvt.l.d {d}, {a}, rdn", a = in(freg) self.0, d = out(reg) d);
            return d;
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            // We use the native conversion (which is a trunc()) and then
            // subtract 1 if that yields a value greater than the source.
            // On x86_64, comparison uses SSE2 opcode cmpsd which is then
            // extracted into an integer register as 0 or -1, so the
            // final subtraction will be done in a branchless way.
            // On aarch64, the comparison should use fcmp, and then use the
            // flags in a csel, cset, adc or sbc opcode.
            let x = self.0;
            let r = x as i64;
            return r - ((x < (r as f64)) as i64);
        }
    }

    #[inline(always)]
    pub(crate) fn trunc(self) -> i64 {
        self.0 as i64
    }

    #[inline(always)]
    pub(crate) fn set_add(&mut self, other: Self) {
        self.0 += other.0;
    }

    #[inline(always)]
    pub(crate) fn set_sub(&mut self, other: Self) {
        self.0 -= other.0;
    }

    // Negation.
    #[inline(always)]
    pub(crate) fn set_neg(&mut self) {
        self.0 = -self.0;
    }

    #[inline(always)]
    pub(crate) fn set_mul(&mut self, other: Self) {
        self.0 *= other.0;
    }

    #[inline(always)]
    pub(crate) fn square(self) -> Self {
        Self(self.0 * self.0)
    }

    #[cfg(feature = "div_emu")]
    #[inline]
    pub(crate) fn set_div(&mut self, other: Self) {
        let x = u64::from_le_bytes(self.0.to_le_bytes());
        let y = u64::from_le_bytes(other.0.to_le_bytes());
        let z = Self::div_emu(x, y);
        self.0 = f64::from_le_bytes(z.to_le_bytes());
    }

    #[cfg(not(feature = "div_emu"))]
    #[inline(always)]
    pub(crate) fn set_div(&mut self, other: Self) {
        self.0 /= other.0;
    }

    #[allow(dead_code)]
    pub(crate) fn abs(self) -> Self {
        // This is for tests, thus it does not need to be constant-time.
        // (it could be made constant-time with intrinsics)
        if self.0 < 0.0 { Self(-self.0) } else { self }
    }

    pub(crate) fn sqrt(self) -> Self {
        #[cfg(not(feature = "sqrt_emu"))]
        {
            // f64::sqrt() is in std but not in core. We use the
            // architecture-specific intrinsics.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                // x86 (64-bit): use SSE2
                use core::arch::x86_64::*;
                let x = _mm_set_sd(self.0);
                let x = _mm_sqrt_pd(x);
                return Self(_mm_cvtsd_f64(x));
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
            unsafe {
                // An f64 is already in a SIMD register, we use a transmute
                // to make it look like a float64x1_t, but that should be
                // a no-op in compiled code.
                use core::arch::aarch64::*;
                let x: float64x1_t = core::mem::transmute(self.0);
                let x = vsqrt_f64(x);
                return Self(core::mem::transmute(x));
            }

            #[cfg(target_arch = "riscv64")]
            unsafe {
                use core::arch::asm;
                let mut d: f64;
                asm!("fsqrt.d {d}, {a}", a = in(freg) self.0, d = out(freg) d);
                return Self(d);
            }
        }

        #[cfg(any(
            feature = "sqrt_emu",
            not(any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "arm64ec",
                target_arch = "riscv64"
            ))
        ))]
        {
            let x = u64::from_le_bytes(self.0.to_le_bytes());
            let z = Self::sqrt_emu(x);
            return Self(f64::from_le_bytes(z.to_le_bytes()));
        }
    }

    // Emulated division with integer operations only; this is meant for
    // architectures where native floating-point can be used, but the
    // division operation is not constant-time enough.
    #[cfg(feature = "div_emu")]
    fn div_emu(x: u64, y: u64) -> u64 {
        // see FLR::set_div() in flr_emu.rs for details
        const M52: u64 = 0x000FFFFFFFFFFFFF;
        let mut xu = (x & M52) | (1u64 << 52);
        let yu = (y & M52) | (1u64 << 52);

        let mut q = 0;
        for _ in 0..55 {
            let b = (xu.wrapping_sub(yu) >> 63).wrapping_sub(1);
            xu -= b & yu;
            q |= b & 1;
            xu <<= 1;
            q <<= 1;
        }

        q |= (xu | xu.wrapping_neg()) >> 63;

        let es = ((q >> 55) as u32) & 1;
        q = (q >> es) | (q & 1);

        let ex = ((x >> 52) as i32) & 0x7FF;
        let ey = ((y >> 52) as i32) & 0x7FF;
        let e = ex - ey - 55 + (es as i32);

        let s = (x ^ y) >> 63;

        let dz = (ex - 1) >> 16;
        let e = e ^ (dz & (e ^ -1076));
        let dm = !((dz as i64) as u64);
        let s = s & dm;
        q &= dm;
        let cc = (0xC8u64 >> ((q as u32) & 7)) & 1;
        (s << 63) + (((e + 1076) as u64) << 52) + (q >> 2) + cc
    }

    // Emulated square root with integer operations only; this is meant for
    // architectures where native floating-point can be used, but the
    // square root operation is not constant-time enough. It is also used
    // for architecture other than the ones supported directly in sqrt()
    // (square root extraction normally uses a standard library function,
    // which we cannot use since this is a no_std library).
    #[cfg(any(
        feature = "sqrt_emu",
        not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))
    ))]
    fn sqrt_emu(x: u64) -> u64 {
        // see FLR::sqrt() in flr_emu.rs for details
        const M52: u64 = 0x000FFFFFFFFFFFFF;
        let mut xu = (x & M52) | (1u64 << 52);
        let ex = ((x >> 52) as u32) & 0x7FF;
        let mut e = (ex as i32) - 1023;

        xu += ((-(e & 1) as i64) as u64) & xu;
        e >>= 1;

        xu <<= 1;

        let mut q = 0;
        let mut s = 0;
        let mut r = 1u64 << 53;
        for _ in 0..54 {
            let t = s + r;
            let b = (xu.wrapping_sub(t) >> 63).wrapping_sub(1);
            s += (r << 1) & b;
            xu -= t & b;
            q += r & b;
            xu <<= 1;
            r >>= 1;
        }

        q <<= 1;
        q |= (xu | xu.wrapping_neg()) >> 63;

        e -= 54;

        q &= (((ex + 0x7FF) >> 11) as u64).wrapping_neg();
        let t = ((q >> 54) as u32).wrapping_neg();
        let e = ((e + 1076) as u32) & t;
        let cc = (0xC8u64 >> ((q as u32) & 7)) & 1;
        ((e as u64) << 52) + (q >> 2) + cc
    }

    pub(crate) fn expm_p63(self, ccs: Self) -> u64 {
        // For full reproducibility of test vectors, we should take care
        // to always return the same values as the emulated code.

        // The polynomial approximation of exp(-x) is from FACCT:
        //   https://eprint.iacr.org/2018/1234
        // Specifically, the values are extracted from the implementation
        // referenced by FACCT, available at:
        //   https://github.com/raykzhao/gaussian
        let mut y = Self::EXPM_COEFFS[0];
        let z = (self.mul2p63().trunc() as u64) << 1;

        // On 64-bit platforms, we assume that 64x64->128 multiplications
        // are constant-time. This is known to be slightly wrong on some
        // low-end aarch64 (e.g. ARM Cortex A53 and A55), where
        // multiplications are a bit faster when operands are small (i.e.
        // fit on 32 bits).
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))]
        {
            for i in 1..Self::EXPM_COEFFS.len() {
                // Compute z*y over 128 bits, but keep only the top 64 bits.
                let yy = (z as u128) * (y as u128);
                y = Self::EXPM_COEFFS[i].wrapping_sub((yy >> 64) as u64);
            }

            // The scaling factor must be applied at the end. Since y is now
            // in fixed-point notation, we have to convert the factor to the
            // same format, and we do an extra integer multiplication.
            let z = (ccs.mul2p63().trunc() as u64) << 1;
            return (((z as u128) * (y as u128)) >> 64) as u64;
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        {
            let (z0, z1) = (z as u32, (z >> 32) as u32);
            for i in 1..Self::EXPM_COEFFS.len() {
                // Compute z*y over 128 bits, but keep only the top 64 bits.
                // We stick to 32-bit multiplications for the same reasons
                // as in set_mul().
                let (y0, y1) = (y as u32, (y >> 32) as u32);
                let f = (z0 as u64) * (y0 as u64);
                let a = (z0 as u64) * (y1 as u64) + (f >> 32);
                let b = (z1 as u64) * (y0 as u64);
                let c = (a >> 32)
                    + (b >> 32)
                    + ((((a as u32) as u64) + ((b as u32) as u64)) >> 32)
                    + (z1 as u64) * (y1 as u64);
                y = Self::EXPM_COEFFS[i].wrapping_sub(c);
            }

            // The scaling factor must be applied at the end. Since y is now
            // in fixed-point notation, we have to convert the factor to the
            // same format, and we do an extra integer multiplication.
            let z = (ccs.mul2p63().trunc() as u64) << 1;
            let (z0, z1) = (z as u32, (z >> 32) as u32);
            let (y0, y1) = (y as u32, (y >> 32) as u32);
            let f = (z0 as u64) * (y0 as u64);
            let a = (z0 as u64) * (y1 as u64) + (f >> 32);
            let b = (z1 as u64) * (y0 as u64);
            let y = (a >> 32)
                + (b >> 32)
                + ((((a as u32) as u64) + ((b as u32) as u64)) >> 32)
                + (z1 as u64) * (y1 as u64);
            return y;
        }
    }

    const EXPM_COEFFS: [u64; 13] = [
        0x00000004741183A3,
        0x00000036548CFC06,
        0x0000024FDCBF140A,
        0x0000171D939DE045,
        0x0000D00CF58F6F84,
        0x000680681CF796E3,
        0x002D82D8305B0FEA,
        0x011111110E066FD0,
        0x0555555555070F00,
        0x155555555581FF00,
        0x400000000002B400,
        0x7FFFFFFFFFFF4800,
        0x8000000000000000,
    ];
}
