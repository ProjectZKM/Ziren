component                                                     bytes   share
vk (StarkVerifyingKey)                                          684    0.1%
proof.public_values                                             932    0.1%
basefold_shard_proof (all)                                   856685   99.8%
  public_values                                                 932    0.1%
  main_commitment                                                32    0.0%
  logup_gkr_proof                                             53536    6.2%
    circuit_output                                             8208    1.0%
    round_proofs (x21)                                        35624    4.2%
    logup_evaluations                                          9700    1.1%
  zerocheck_proof (22 rounds)                                  2336    0.3%
  opened_values (8 chips)                                     13144    1.5%
    main                                                       6400    0.7%
    permutation                                                 128    0.0%
    preprocessed                                               2896    0.3%
    quotient                                                   3072    0.4%
  chip_heights                                                  212    0.0%
  chip_cumulative_sums                                          724    0.1%
  row_counts + padding_column_counts                            200    0.0%
  evaluation_proof (jagged bundle)                           785413   91.5%
    reduction (jagged sumcheck)                                1824    0.2%
    jagged_eval (eval sumcheck)                                4224    0.5%
    basefold_proof (inner BaseFold, unused w/ WHIR)              64    0.0%
    y_per_chip                                                 9296    1.1%
    commit                                                       72    0.0%
    packing                                                    5112    0.6%
    whir_proof (stacked)                                     764724   89.1%
      batch_evaluations                                        1560    0.2%
      round_query_openings (x3 rounds)                       761720   88.7%
        round 0 (168 leaves)                                 680072   79.2%
          first leaf: 40 matrices, 640 opened felts, 18 path nodes       3472    0.4%
            values                                             2888    0.3%
            path                                                584    0.1%
        round 1 (21 leaves)                                   52928    6.2%
          first leaf: 1 matrices, 512 opened felts, 14 path nodes       2520    0.3%
            values                                             2064    0.2%
            path                                                456    0.1%
        round 2 (12 leaves)                                   28712    3.3%
          first leaf: 1 matrices, 512 opened felts, 10 path nodes       2392    0.3%
            values                                             2064    0.2%
            path                                                328    0.0%
      round_sumcheck_polys                                      640    0.1%
      final_sumcheck_polys                                      400    0.0%
      round_ood_answers                                          88    0.0%
      round_commitments                                          88    0.0%
      final_poly                                                136    0.0%
      pow                                                        92    0.0%
TOTAL (file)                                                 858306
