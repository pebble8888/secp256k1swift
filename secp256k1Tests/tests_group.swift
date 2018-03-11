//
//  tests_group.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/11.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation
@testable import secp256k1

/***** GROUP TESTS *****/

func ge_equals_ge(_ a: secp256k1_ge, _ b:secp256k1_ge) {
    CHECK(a.infinity == b.infinity);
    if (a.infinity) {
        return;
    }
    CHECK(secp256k1_fe_equal_var(a.x, b.x));
    CHECK(secp256k1_fe_equal_var(a.y, b.y));
}

/* This compares jacobian points including their Z, not just their geometric meaning. */
func gej_xyz_equals_gej(_ a: secp256k1_gej, _ b: secp256k1_gej) -> Bool {
    var a2 = secp256k1_gej()
    var b2 = secp256k1_gej()
    var ret:Bool = true
    ret = ret && (a.infinity == b.infinity)
    if (ret && !a.infinity) {
        a2 = a;
        b2 = b;
        secp256k1_fe_normalize(&a2.x);
        secp256k1_fe_normalize(&a2.y);
        secp256k1_fe_normalize(&a2.z);
        secp256k1_fe_normalize(&b2.x);
        secp256k1_fe_normalize(&b2.y);
        secp256k1_fe_normalize(&b2.z);
        ret = ret && (secp256k1_fe_cmp_var(a2.x, b2.x) == 0)
        ret = ret && (secp256k1_fe_cmp_var(a2.y, b2.y) == 0)
        ret = ret && (secp256k1_fe_cmp_var(a2.z, b2.z) == 0)
    }
    return ret;
}

func ge_equals_gej(_ a: secp256k1_ge, _ b: secp256k1_gej) {
    var z2s = secp256k1_fe()
    var u1 = secp256k1_fe()
    var u2 = secp256k1_fe()
    var s1 = secp256k1_fe()
    var s2 = secp256k1_fe()
    CHECK(a.infinity == b.infinity);
    if (a.infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    secp256k1_fe_sqr(&z2s, b.z);
    secp256k1_fe_mul(&u1, a.x, z2s);
    u2 = b.x; secp256k1_fe_normalize_weak(&u2);
    secp256k1_fe_mul(&s1, a.y, z2s); secp256k1_fe_mul(&s1, s1, b.z);
    s2 = b.y; secp256k1_fe_normalize_weak(&s2);
    CHECK(secp256k1_fe_equal_var(u1, u2));
    CHECK(secp256k1_fe_equal_var(s1, s2));
}




func test_ge() {
    /*
#if USE_ENDOMORPHISM
    int runs = 6;
#else
    */
    let runs:Int = 4;
/*
#endif
 */
    /* Points: (infinity, p1, p1, -p1, -p1, p2, p2, -p2, -p2, p3, p3, -p3, -p3, p4, p4, -p4, -p4).
     * The second in each pair of identical points uses a random Z coordinate in the Jacobian form.
     * All magnitudes are randomized.
     * All 17*17 combinations of points are added to each other, using all applicable methods.
     *
     * When the endomorphism code is compiled in, p5 = lambda*p1 and p6 = lambda^2*p1 are added as well.
     */
    var ge = [secp256k1_ge](repeating: secp256k1_ge(), count: 1 + 4 * runs) //  *ge = (secp256k1_ge *)checked_malloc(&ctx.error_callback, sizeof(secp256k1_ge) * (1 + 4 * runs));
    var gej = [secp256k1_gej](repeating: secp256k1_gej(), count: 1 + 4 * runs) // *gej = (secp256k1_gej *)checked_malloc(&ctx.error_callback, sizeof(secp256k1_gej) * (1 + 4 * runs));
    var zinv = [secp256k1_fe](repeating: secp256k1_fe(), count: 1 + 4 * runs) // *zinv = (secp256k1_fe *)checked_malloc(&ctx.error_callback, sizeof(secp256k1_fe) * (1 + 4 * runs));
    var zf = secp256k1_fe()
    var zfi2 = secp256k1_fe()
    var zfi3 = secp256k1_fe()

    secp256k1_gej_set_infinity(&gej[0]);
    secp256k1_ge_clear(&ge[0]);
    secp256k1_ge_set_gej_var(&ge[0], &gej[0]);
    for i in 0 ..< runs {
        var g = secp256k1_ge()
        random_group_element_test(&g);
        /*
#ifdef USE_ENDOMORPHISM
        if (i >= runs - 2) {
            secp256k1_ge_mul_lambda(&g, &ge[1]);
        }
        if (i >= runs - 1) {
            secp256k1_ge_mul_lambda(&g, &g);
        }
#endif
        */
        ge[1 + 4 * i] = g;
        ge[2 + 4 * i] = g;
        secp256k1_ge_neg(&ge[3 + 4 * i], g);
        secp256k1_ge_neg(&ge[4 + 4 * i], g);
        secp256k1_gej_set_ge(&gej[1 + 4 * i], ge[1 + 4 * i]);
        random_group_element_jacobian_test(&gej[2 + 4 * i], ge[2 + 4 * i]);
        secp256k1_gej_set_ge(&gej[3 + 4 * i], ge[3 + 4 * i]);
        random_group_element_jacobian_test(&gej[4 + 4 * i], ge[4 + 4 * i]);
        for j in 0 ..< 4 {
            random_field_element_magnitude(&ge[1 + j + 4 * i].x);
            random_field_element_magnitude(&ge[1 + j + 4 * i].y);
            random_field_element_magnitude(&gej[1 + j + 4 * i].x);
            random_field_element_magnitude(&gej[1 + j + 4 * i].y);
            random_field_element_magnitude(&gej[1 + j + 4 * i].z);
        }
    }

    /* Compute z inverses. */
    do {
        var zs = [secp256k1_fe](repeating: secp256k1_fe(), count: 1 + 4 * runs) // = checked_malloc(&ctx.error_callback, sizeof(secp256k1_fe) * (1 + 4 * runs));
        for i in 0 ..< 4 * runs + 1 {
            if (i == 0) {
                /* The point at infinity does not have a meaningful z inverse. Any should do. */
                repeat {
                    random_field_element_test(&zs[i]);
                } while(secp256k1_fe_is_zero(zs[i]));
            } else {
                zs[i] = gej[i].z;
            }
        }
        secp256k1_fe_inv_all_var(&zinv, zs, UInt(4 * runs + 1));
        //free(zs);
    }

    /* Generate random zf, and zfi2 = 1/zf^2, zfi3 = 1/zf^3 */
    repeat {
        random_field_element_test(&zf);
    } while(secp256k1_fe_is_zero(zf));
    random_field_element_magnitude(&zf);
    secp256k1_fe_inv_var(&zfi3, zf);
    secp256k1_fe_sqr(&zfi2, zfi3);
    secp256k1_fe_mul(&zfi3, zfi3, zfi2);

    for i1 in 0 ..< 1 + 4 * runs {
        for i2 in 0 ..< 1 + 4 * runs {
            /* Compute reference result using gej + gej (var). */
            var refj = secp256k1_gej()
            var resj = secp256k1_gej()
            var ref = secp256k1_ge()
            var zr = secp256k1_fe()
            var dummy = secp256k1_fe()
            
            if secp256k1_gej_is_infinity(gej[i1]) {
                secp256k1_gej_add_var(&refj, gej[i1], gej[i2], &dummy)
            } else {
                secp256k1_gej_add_var(&refj, gej[i1], gej[i2], &zr)
            }
            /* Check Z ratio. */
            if (!secp256k1_gej_is_infinity(gej[i1]) && !secp256k1_gej_is_infinity(refj)) {
                var zrz = secp256k1_fe(); secp256k1_fe_mul(&zrz, zr, gej[i1].z);
                CHECK(secp256k1_fe_equal_var(zrz, refj.z));
            }
            secp256k1_ge_set_gej_var(&ref, &refj);

            /* Test gej + ge with Z ratio result (var). */
            if secp256k1_gej_is_infinity(gej[i1]) {
                secp256k1_gej_add_ge_var(&resj, gej[i1], ge[i2], &dummy)
            } else {
                secp256k1_gej_add_ge_var(&resj, gej[i1], ge[i2], &zr)
            }
            ge_equals_gej(ref, resj);
            if (!secp256k1_gej_is_infinity(gej[i1]) && !secp256k1_gej_is_infinity(resj)) {
                var zrz = secp256k1_fe(); secp256k1_fe_mul(&zrz, zr, gej[i1].z);
                CHECK(secp256k1_fe_equal_var(zrz, resj.z));
            }

            /* Test gej + ge (var, with additional Z factor). */
            do {
                var ge2_zfi = ge[i2]; /* the second term with x and y rescaled for z = 1/zf */
                secp256k1_fe_mul(&ge2_zfi.x, ge2_zfi.x, zfi2);
                secp256k1_fe_mul(&ge2_zfi.y, ge2_zfi.y, zfi3);
                random_field_element_magnitude(&ge2_zfi.x);
                random_field_element_magnitude(&ge2_zfi.y);
                secp256k1_gej_add_zinv_var(&resj, gej[i1], ge2_zfi, zf);
                ge_equals_gej(ref, resj);
            }

            /* Test gej + ge (const). */
            if (i2 != 0) {
                /* secp256k1_gej_add_ge does not support its second argument being infinity. */
                secp256k1_gej_add_ge(&resj, gej[i1], ge[i2]);
                ge_equals_gej(ref, resj);
            }

            /* Test doubling (var). */
            if ((i1 == 0 && i2 == 0) || ((i1 + 3)/4 == (i2 + 3)/4 && ((i1 + 3)%4)/2 == ((i2 + 3)%4)/2)) {
                var zr2 = secp256k1_fe()
                /* Normal doubling with Z ratio result. */
                secp256k1_gej_double_var(&resj, gej[i1], &zr2);
                ge_equals_gej(ref, resj);
                /* Check Z ratio. */
                secp256k1_fe_mul(&zr2, zr2, gej[i1].z);
                CHECK(secp256k1_fe_equal_var(zr2, resj.z));
                /* Normal doubling. */
                var dummy = secp256k1_fe()
                secp256k1_gej_double_var(&resj, gej[i2], &dummy);
                ge_equals_gej(ref, resj);
            }

            /* Test adding opposites. */
            if ((i1 == 0 && i2 == 0) || ((i1 + 3)/4 == (i2 + 3)/4 && ((i1 + 3)%4)/2 != ((i2 + 3)%4)/2)) {
                CHECK(secp256k1_ge_is_infinity(ref));
            }

            /* Test adding infinity. */
            if (i1 == 0) {
                CHECK(secp256k1_ge_is_infinity(ge[i1]));
                CHECK(secp256k1_gej_is_infinity(gej[i1]));
                ge_equals_gej(ref, gej[i2]);
            }
            if (i2 == 0) {
                CHECK(secp256k1_ge_is_infinity(ge[i2]));
                CHECK(secp256k1_gej_is_infinity(gej[i2]));
                ge_equals_gej(ref, gej[i1]);
            }
        }
    }

    /* Test adding all points together in random order equals infinity. */
    do {
        var sum: secp256k1_gej = SECP256K1_GEJ_CONST_INFINITY;
        var gej_shuffled = [secp256k1_gej](repeating: secp256k1_gej(), count: 4 * runs + 1) // = (secp256k1_gej *)checked_malloc(&ctx.error_callback, (4 * runs + 1) * sizeof(secp256k1_gej));
        for i in 0 ..< 4 * runs + 1 {
            gej_shuffled[i] = gej[i];
        }
        for i in 0 ..< 4 * runs + 1 {
            let swap:Int = Int(i) + Int(secp256k1_rand_int(UInt32(4 * runs + 1 - i)))
            if (swap != i) {
                let t: secp256k1_gej = gej_shuffled[i];
                gej_shuffled[i] = gej_shuffled[swap];
                gej_shuffled[swap] = t;
            }
        }
        for i in 0 ..< 4 * runs + 1 {
            var dummy = secp256k1_fe()
            secp256k1_gej_add_var(&sum, sum, gej_shuffled[i], &dummy);
        }
        CHECK(secp256k1_gej_is_infinity(sum));
        //free(gej_shuffled);
    }

    /* Test batch gej -> ge conversion with and without known z ratios. */
    do {
        var zr = [secp256k1_fe](repeating: secp256k1_fe(), count: 4 * runs + 1) // *zr = (secp256k1_fe *)checked_malloc(&ctx.error_callback, (4 * runs + 1) * sizeof(secp256k1_fe));
        var ge_set_table = [secp256k1_ge](repeating: secp256k1_ge(), count: Int(4 * runs + 1)) // *ge_set_table = (secp256k1_ge *)checked_malloc(&ctx.error_callback, (4 * runs + 1) * sizeof(secp256k1_ge));
        var ge_set_all = [secp256k1_ge](repeating: secp256k1_ge(), count: Int(4 * runs + 1)) // *ge_set_all = (secp256k1_ge *)checked_malloc(&ctx.error_callback, (4 * runs + 1) * sizeof(secp256k1_ge));
        for i in 0 ..< 4 * runs + 1 {
            /* Compute gej[i + 1].z / gez[i].z (with gej[n].z taken to be 1). */
            if (i < 4 * runs) {
                secp256k1_fe_mul(&zr[i + 1], zinv[i], gej[i + 1].z);
            }
        }
        secp256k1_ge_set_table_gej_var(&ge_set_table, gej, zr, UInt(4 * runs + 1));
        secp256k1_ge_set_all_gej_var(&ge_set_all, gej, UInt(4 * runs + 1), ctx?.error_callback);
        for i in 0 ..< 4 * runs + 1 {
            var s = secp256k1_fe()
            random_fe_non_zero(&s);
            secp256k1_gej_rescale(&gej[i], s);
            ge_equals_gej(ge_set_table[i], gej[i]);
            ge_equals_gej(ge_set_all[i], gej[i]);
        }
        //free(ge_set_table);
        //free(ge_set_all);
        //free(zr);
    }

    //free(ge);
    //free(gej);
    //free(zinv);
}

func test_add_neg_y_diff_x() {
    /* The point of this test is to check that we can add two points
     * whose y-coordinates are negatives of each other but whose x
     * coordinates differ. If the x-coordinates were the same, these
     * points would be negatives of each other and their sum is
     * infinity. This is cool because it "covers up" any degeneracy
     * in the addition algorithm that would cause the xy coordinates
     * of the sum to be wrong (since infinity has no xy coordinates).
     * HOWEVER, if the x-coordinates are different, infinity is the
     * wrong answer, and such degeneracies are exposed. This is the
     * root of https://github.com/bitcoin-core/secp256k1/issues/257
     * which this test is a regression test for.
     *
     * These points were generated in sage as
     * # secp256k1 params
     * F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
     * C = EllipticCurve ([F (0), F (7)])
     * G = C.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
     * N = FiniteField(G.order())
     *
     * # endomorphism values (lambda is 1^{1/3} in N, beta is 1^{1/3} in F)
     * x = polygen(N)
     * lam  = (1 - x^3).roots()[1][0]
     *
     * # random "bad pair"
     * P = C.random_element()
     * Q = -int(lam) * P
     * print "    P: %x %x" % P.xy()
     * print "    Q: %x %x" % Q.xy()
     * print "P + Q: %x %x" % (P + Q).xy()
     */
    let aj: secp256k1_gej = SECP256K1_GEJ_CONST(
        0x8d24cd95, 0x0a355af1, 0x3c543505, 0x44238d30,
        0x0643d79f, 0x05a59614, 0x2f8ec030, 0xd58977cb,
        0x001e337a, 0x38093dcd, 0x6c0f386d, 0x0b1293a8,
        0x4d72c879, 0xd7681924, 0x44e6d2f3, 0x9190117d
    );
    var bj: secp256k1_gej = SECP256K1_GEJ_CONST(
        0xc7b74206, 0x1f788cd9, 0xabd0937d, 0x164a0d86,
        0x95f6ff75, 0xf19a4ce9, 0xd013bd7b, 0xbf92d2a7,
        0xffe1cc85, 0xc7f6c232, 0x93f0c792, 0xf4ed6c57,
        0xb28d3786, 0x2897e6db, 0xbb192d0b, 0x6e6feab2
    );
    let sumj: secp256k1_gej = SECP256K1_GEJ_CONST(
        0x671a63c0, 0x3efdad4c, 0x389a7798, 0x24356027,
        0xb3d69010, 0x278625c3, 0x5c86d390, 0x184a8f7a,
        0x5f6409c2, 0x2ce01f2b, 0x511fd375, 0x25071d08,
        0xda651801, 0x70e95caf, 0x8f0d893c, 0xbed8fbbe
    );
    var b = secp256k1_ge()
    var resj = secp256k1_gej()
    var res = secp256k1_ge()
    secp256k1_ge_set_gej(&b, &bj);

    var dummy = secp256k1_fe()
    secp256k1_gej_add_var(&resj, aj, bj, &dummy);
    secp256k1_ge_set_gej(&res, &resj);
    ge_equals_gej(res, sumj);

    secp256k1_gej_add_ge(&resj, aj, b);
    secp256k1_ge_set_gej(&res, &resj);
    ge_equals_gej(res, sumj);

    secp256k1_gej_add_ge_var(&resj, aj, b, &dummy);
    secp256k1_ge_set_gej(&res, &resj);
    ge_equals_gej(res, sumj);
}

func run_ge() {
    for _ in 0 ..< g_count * 32 {
        test_ge();
    }
    test_add_neg_y_diff_x();
}

/*
func test_group_decompress(_ x: secp256k1_fe) {
    /* The input itself, normalized. */
    secp256k1_fe fex = *x;
    secp256k1_fe fez;
    /* Results of set_xquad_var, set_xo_var(..., 0), set_xo_var(..., 1). */
    secp256k1_ge ge_quad, ge_even, ge_odd;
    secp256k1_gej gej_quad;
    /* Return values of the above calls. */
    int res_quad, res_even, res_odd;

    secp256k1_fe_normalize_var(&fex);

    res_quad = secp256k1_ge_set_xquad(&ge_quad, &fex);
    res_even = secp256k1_ge_set_xo_var(&ge_even, &fex, 0);
    res_odd = secp256k1_ge_set_xo_var(&ge_odd, &fex, 1);

    CHECK(res_quad == res_even);
    CHECK(res_quad == res_odd);

    if (res_quad) {
        secp256k1_fe_normalize_var(&ge_quad.x);
        secp256k1_fe_normalize_var(&ge_odd.x);
        secp256k1_fe_normalize_var(&ge_even.x);
        secp256k1_fe_normalize_var(&ge_quad.y);
        secp256k1_fe_normalize_var(&ge_odd.y);
        secp256k1_fe_normalize_var(&ge_even.y);

        /* No infinity allowed. */
        CHECK(!ge_quad.infinity);
        CHECK(!ge_even.infinity);
        CHECK(!ge_odd.infinity);

        /* Check that the x coordinates check out. */
        CHECK(secp256k1_fe_equal_var(&ge_quad.x, x));
        CHECK(secp256k1_fe_equal_var(&ge_even.x, x));
        CHECK(secp256k1_fe_equal_var(&ge_odd.x, x));

        /* Check that the Y coordinate result in ge_quad is a square. */
        CHECK(secp256k1_fe_is_quad_var(&ge_quad.y));

        /* Check odd/even Y in ge_odd, ge_even. */
        CHECK(secp256k1_fe_is_odd(&ge_odd.y));
        CHECK(!secp256k1_fe_is_odd(&ge_even.y));

        /* Check secp256k1_gej_has_quad_y_var. */
        secp256k1_gej_set_ge(&gej_quad, &ge_quad);
        CHECK(secp256k1_gej_has_quad_y_var(&gej_quad));
        do {
            random_fe_test(&fez);
        } while (secp256k1_fe_is_zero(&fez));
        secp256k1_gej_rescale(&gej_quad, &fez);
        CHECK(secp256k1_gej_has_quad_y_var(&gej_quad));
        secp256k1_gej_neg(&gej_quad, &gej_quad);
        CHECK(!secp256k1_gej_has_quad_y_var(&gej_quad));
        do {
            random_fe_test(&fez);
        } while (secp256k1_fe_is_zero(&fez));
        secp256k1_gej_rescale(&gej_quad, &fez);
        CHECK(!secp256k1_gej_has_quad_y_var(&gej_quad));
        secp256k1_gej_neg(&gej_quad, &gej_quad);
        CHECK(secp256k1_gej_has_quad_y_var(&gej_quad));
    }
}

func run_group_decompress() {
    int i;
    for (i = 0; i < g_count * 4; i++) {
        secp256k1_fe fe;
        random_fe_test(&fe);
        test_group_decompress(&fe);
    }
}

*/
