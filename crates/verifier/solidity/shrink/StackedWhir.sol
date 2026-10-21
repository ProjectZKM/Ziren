// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {KoalaBear as F} from "./KoalaBear.sol";
import {KeccakTranscript as T} from "./KeccakTranscript.sol";

/// Direct port of StackedWhirVerifier::verify_trusted_evaluation.
/// This PCS component is NOT the complete Ziren machine verifier. The caller
/// must authenticate all configuration, roots, stripe counts, stack point,
/// incoming transcript and the batch-evaluation claims from the jagged layer.
library StackedWhir {
    using T for T.State;

    struct Round {
        uint256 fold;
        uint256 rate;
        uint256 queries;
        uint256 ood;
        uint256 queryPow;
        uint256[] foldPow;
    }

    struct Config {
        uint256 n;
        uint256 startingRate;
        uint256 batchPow;
        uint256 finalQueries;
        uint256 finalPow;
        Round[] rounds;
    }

    struct Leaf {
        uint256[][] values;
        bytes32[] path;
        // Optional bounded view into the original LE32 proof stream. An empty
        // source selects the independent materialized reference representation.
        bytes source;
        uint256 offset;
        uint256 rows;
        uint256 width;
    }

    struct Proof {
        uint256[][] batch;
        uint256 batchPow;
        uint256[][][] roundPolys;
        uint256[][] roundOod;
        bytes32[] roots;
        Leaf[][] openings;
        uint256[] finalPoly;
        uint256[][] finalPolys;
        uint256[] foldPow;
        uint256 finalPow;
    }

    struct Constraint {
        uint256[] point;
        uint256 coeff;
        uint256 vars;
        bool monomial;
    }

    struct Work {
        uint256 claim;
        uint256[][] lambdaPowers;
        Constraint[] constraints;
        uint256 count;
        uint256[] randomness;
        uint256 folded;
        uint256 powAt;
        uint256 domainLog;
    }
    error InvalidWhir(uint256 stage);

    function generator(uint256 log) internal pure returns (uint256) {
        uint256[25] memory g = [
            uint256(0x1),
            0x7f000000,
            0x7e010002,
            0x6832fe4a,
            0x8dbd69c,
            0xa28f031,
            0x5c4a5b99,
            0x29b75a80,
            0x17668b8a,
            0x27ad539b,
            0x334d48c7,
            0x7744959c,
            0x768fc6fa,
            0x303964b2,
            0x3e687d4d,
            0x45a60e61,
            0x6e2f4d7a,
            0x163bd499,
            0x6c4a8a45,
            0x143ef899,
            0x514ddcad,
            0x484ef19b,
            0x205d63c3,
            0x68e7dd49,
            0x6ac49f88
        ];
        if (log > 24) revert InvalidWhir(1);
        return g[log];
    }

    function validate(
        Proof memory p,
        Config memory c,
        uint256[] memory stripes,
        uint256[] memory point,
        bytes32[] memory roots
    ) private pure returns (uint256 finalLog) {
        uint256 rounds = c.rounds.length;
        require(rounds > 0 && rounds <= 24 && c.n <= 24, "WHIR config");
        uint256 folds;
        for (uint256 r; r < rounds; ++r) {
            folds += c.rounds[r].fold;
            require(c.rounds[r].foldPow.length == c.rounds[r].fold, "fold difficulty count");
        }
        require(folds <= c.n && point.length == c.n, "stack dimension");
        finalLog = c.n - folds;
        require(p.finalPoly.length == 1 << finalLog && p.finalPolys.length == c.rounds[rounds - 1].fold, "final shape");
        require(
            p.roots.length == rounds - 1 && p.roundOod.length == rounds - 1 && p.roundPolys.length == rounds - 1
                && p.openings.length == rounds,
            "round shape"
        );
        require(
            p.foldPow.length == folds + rounds - 1 && p.batch.length == stripes.length
                && roots.length == stripes.length,
            "batch shape"
        );
        for (uint256 r; r < p.batch.length; ++r) {
            require(p.batch[r].length == stripes[r], "stripe count");
            checkEs(p.batch[r]);
        }
        for (uint256 r; r < rounds - 1; ++r) {
            require(
                p.roundPolys[r].length == c.rounds[r].fold && p.roundOod[r].length == c.rounds[r].ood,
                "round data shape"
            );
            checkEs(p.roundOod[r]);
            for (uint256 j; j < p.roundPolys[r].length; ++j) {
                require(p.roundPolys[r][j].length == 3, "degree two");
                checkEs(p.roundPolys[r][j]);
            }
        }
        for (uint256 j; j < p.finalPolys.length; ++j) {
            require(p.finalPolys[j].length == 3, "final degree two");
            checkEs(p.finalPolys[j]);
        }
        checkEs(p.finalPoly);
        checkEs(point);
    }

    function checkEs(uint256[] memory xs) private pure {
        for (uint256 i; i < xs.length; ++i) {
            if (!F.canonical(xs[i])) revert F.InvalidField();
        }
    }

    function checkMerkle(Leaf memory leaf, bytes32 root, uint256 index, uint256 height, uint256 rows, uint256 width)
        private
        pure
    {
        require(leaf.path.length == height && index < 1 << height, "Merkle shape");
        bytes32 h;
        if (leaf.source.length != 0) {
            require(leaf.rows == rows && leaf.width == width, "packed Merkle shape");
            uint256 byteCount = 4 * rows * width;
            require(leaf.offset + byteCount <= leaf.source.length, "packed Merkle bounds");
            bytes memory source = leaf.source;
            uint256 offset = leaf.offset;
            bytes4 invalidField = F.InvalidField.selector;
            assembly ("memory-safe") {
                let start := add(add(source, 32), offset)
                let end := add(start, byteCount)
                for { let ptr := start } lt(ptr, end) { ptr := add(ptr, 4) } {
                    let w := mload(ptr)
                    let x := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                    if iszero(lt(x, 0x7f000001)) {
                        mstore(0, invalidField)
                        revert(0, 4)
                    }
                }
                h := keccak256(start, byteCount)
            }
        } else {
            require(leaf.values.length == rows, "Merkle rows");
            // Reserve a final word for unaligned stores of four LE bytes.
            bytes memory words = new bytes(4 * rows * width + 32);
            uint256 at;
            for (uint256 i; i < rows; ++i) {
                uint256[] memory values = leaf.values[i];
                require(values.length == width, "leaf width");
                bytes4 invalidField = F.InvalidField.selector;
                assembly ("memory-safe") {
                    let dst := add(add(words, 32), at)
                    let src := add(values, 32)
                    let end := add(src, mul(width, 32))
                    for {} lt(src, end) {
                        src := add(src, 32)
                        dst := add(dst, 4)
                    } {
                        let x := mload(src)
                        if iszero(lt(x, 0x7f000001)) {
                            mstore(0, invalidField)
                            revert(0, 4)
                        }
                        let word :=
                            or(
                                or(shl(248, and(x, 255)), shl(240, and(shr(8, x), 255))),
                                or(shl(232, and(shr(16, x), 255)), shl(224, and(shr(24, x), 255)))
                            )
                        mstore(dst, word)
                    }
                }
                at += 4 * width;
            }
            assembly ("memory-safe") { h := keccak256(add(words, 32), at) }
        }
        for (uint256 i; i < height; ++i) {
            bytes32 sibling = leaf.path[i];
            assembly ("memory-safe") {
                switch and(index, 1)
                case 0 {
                    mstore(0, h)
                    mstore(32, sibling)
                }
                default {
                    mstore(0, sibling)
                    mstore(32, h)
                }
                h := keccak256(0, 64)
            }
            index >>= 1;
        }
        if (h != root) revert InvalidWhir(2);
    }

    function virtualLeaf(
        Proof memory p,
        bytes32[] memory roots,
        uint256[] memory stripes,
        Work memory w,
        uint256 r,
        uint256 q,
        uint256 index,
        uint256 fold
    ) private pure returns (uint256[] memory values) {
        if (r == 0) {
            values = new uint256[](1 << fold);
            for (uint256 ri; ri < roots.length; ++ri) {
                Leaf memory leaf = p.openings[r][q * roots.length + ri];
                checkMerkle(leaf, roots[ri], index, w.domainLog, stripes[ri], 1 << fold);
                for (uint256 row; row < stripes[ri]; ++row) {
                    if (leaf.source.length == 0) {
                        F.accumulateBaseRow(values, leaf.values[row], w.lambdaPowers[ri][row]);
                    } else {
                        F.accumulatePackedBaseRow(
                            values, leaf.source, leaf.offset + 4 * row * leaf.width, w.lambdaPowers[ri][row]
                        );
                    }
                }
            }
        } else {
            Leaf memory leaf = p.openings[r][q];
            checkMerkle(leaf, p.roots[r - 1], index, w.domainLog, 1, 4 << fold);
            if (leaf.source.length != 0) {
                values = F.packedExtensions(leaf.source, leaf.offset, 1 << fold);
            } else {
                values = new uint256[](1 << fold);
                for (uint256 j; j < values.length; ++j) {
                    for (uint256 k; k < 4; ++k) {
                        values[j] |= leaf.values[0][4 * j + k] << (32 * k);
                    }
                }
            }
        }
    }

    function verify(
        Proof memory p,
        Config memory c,
        bytes32[] memory roots,
        uint256[] memory stripes,
        uint256[] memory point,
        T.State memory t
    ) internal pure {
        uint256 finalLog = validate(p, c, stripes, point, roots);
        uint256 rounds = c.rounds.length;
        Work memory w;
        uint256 constraints = 1;
        for (uint256 r; r < rounds - 1; ++r) {
            constraints += c.rounds[r].ood + c.rounds[r].queries;
        }
        w.constraints = new Constraint[](constraints);
        w.constraints[0] = Constraint(point, 1, c.n, false);
        w.count = 1;
        w.randomness = new uint256[](c.n - finalLog);
        w.lambdaPowers = new uint256[][](p.batch.length);
        for (uint256 r; r < p.batch.length; ++r) {
            for (uint256 j; j < p.batch[r].length; ++j) {
                t.observeE(p.batch[r][j]);
            }
        }
        t.grind(c.batchPow, p.batchPow);
        uint256 lambda = t.sampleE();
        uint256 lp = 1;
        for (uint256 r; r < p.batch.length; ++r) {
            w.lambdaPowers[r] = new uint256[](p.batch[r].length);
            for (uint256 j; j < p.batch[r].length; ++j) {
                w.claim = F.add(w.claim, F.mul(lp, p.batch[r][j]));
                w.lambdaPowers[r][j] = lp;
                lp = F.mul(lp, lambda);
            }
        }
        t.sampleE(); // Native stacked path samples and discards the initial OOD batch.
        w.domainLog = c.n - c.rounds[0].fold + c.startingRate;
        for (uint256 r; r < rounds; ++r) {
            Round memory rc = c.rounds[r];
            uint256[][] memory polys = r + 1 == rounds ? p.finalPolys : p.roundPolys[r];
            uint256 start = w.folded;
            for (uint256 j; j < rc.fold; ++j) {
                uint256[] memory a = polys[j];
                if (F.add(F.add(a[0], a[0]), F.add(a[1], a[2])) != w.claim) revert InvalidWhir(3);
                t.observeE(a[0]);
                t.observeE(a[1]);
                t.observeE(a[2]);
                t.grind(rc.foldPow[j], p.foldPow[w.powAt++]);
                uint256 x = t.sampleE();
                w.randomness[w.folded++] = x;
                w.claim = F.add(a[0], F.mul(x, F.add(a[1], F.mul(a[2], x))));
            }
            if (r + 1 == rounds) break;
            t.observeHash(p.roots[r]);
            uint256 rem = c.n - w.folded;
            uint256[][] memory oodPoints = new uint256[][](rc.ood);
            for (uint256 j; j < rc.ood; ++j) {
                oodPoints[j] = new uint256[](rem);
                for (uint256 k; k < rem; ++k) {
                    oodPoints[j][k] = t.sampleE();
                }
                t.observeE(p.roundOod[r][j]);
            }
            t.grind(rc.queryPow, p.foldPow[w.powAt++]);
            uint256[] memory indices = new uint256[](rc.queries);
            for (uint256 q; q < rc.queries; ++q) {
                indices[q] = t.bits(w.domainLog);
            }
            uint256 leavesPerQuery = r == 0 ? roots.length : 1;
            require(p.openings[r].length == rc.queries * leavesPerQuery, "query opening count");
            uint256[] memory stir = new uint256[](rc.queries);
            uint256[][] memory stirPoints = new uint256[][](rc.queries);
            uint256[] memory foldPoint = F.slice(w.randomness, start, rc.fold);
            uint256 g = generator(w.domainLog);
            for (uint256 q; q < rc.queries; ++q) {
                stir[q] = F.mle(virtualLeaf(p, roots, stripes, w, r, q, indices[q], rc.fold), foldPoint);
                stirPoints[q] = F.powers(F.basePow(g, indices[q]), rem);
            }
            uint256 batch = t.sampleE();
            uint256 coeff = batch;
            for (uint256 j; j < rc.ood; ++j) {
                w.claim = F.add(w.claim, F.mul(coeff, p.roundOod[r][j]));
                w.constraints[w.count++] = Constraint(oodPoints[j], coeff, rem, false);
                coeff = F.mul(coeff, batch);
            }
            for (uint256 q; q < rc.queries; ++q) {
                w.claim = F.add(w.claim, F.mul(coeff, stir[q]));
                w.constraints[w.count++] = Constraint(stirPoints[q], coeff, rem, true);
                coeff = F.mul(coeff, batch);
            }
            w.domainLog = rem - c.rounds[r + 1].fold + rc.rate;
        }
        for (uint256 j; j < p.finalPoly.length; ++j) {
            t.observeE(p.finalPoly[j]);
        }
        t.grind(c.finalPow, p.finalPow);
        uint256 finalRound = rounds - 1;
        uint256 lastFold = c.rounds[finalRound].fold;
        require(
            p.openings[finalRound].length == c.finalQueries * (finalRound == 0 ? roots.length : 1), "final query count"
        );
        uint256[] memory lastPoint = F.slice(w.randomness, w.randomness.length - lastFold, lastFold);
        uint256 gf = generator(w.domainLog);
        for (uint256 q; q < c.finalQueries; ++q) {
            uint256 index = t.bits(w.domainLog);
            uint256 folded = F.mle(virtualLeaf(p, roots, stripes, w, finalRound, q, index, lastFold), lastPoint);
            if (folded != F.hornerBase(p.finalPoly, F.basePow(gf, index))) revert InvalidWhir(4);
        }
        uint256 total;
        for (uint256 i; i < w.count; ++i) {
            Constraint memory a = w.constraints[i];
            uint256 k = a.vars - finalLog;
            uint256 factor = 1;
            for (uint256 j; j < k; ++j) {
                uint256 y = w.randomness[c.n - a.vars + j];
                factor = F.mul(
                    factor,
                    a.monomial
                        ? F.add(F.sub(1, y), F.mul(y, a.point[j]))
                        : F.add(F.mul(a.point[j], y), F.mul(F.sub(1, a.point[j]), F.sub(1, y)))
                );
            }
            // Every monomial constraint was constructed above from base
            // powers [x,x^2,...]; its tail is the same sequence at x^(2^k).
            uint256 eval = a.monomial
                ? F.hornerBase(p.finalPoly, finalLog == 0 ? 0 : a.point[k])
                : F.mle(p.finalPoly, F.slice(a.point, k, finalLog));
            total = F.add(total, F.mul(a.coeff, F.mul(factor, eval)));
        }
        if (total != w.claim) revert InvalidWhir(5);
    }
}
