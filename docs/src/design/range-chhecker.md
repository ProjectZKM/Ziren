# Range Checker

A range checker is to check the values are in the given range.

zkMIPS relies very heavily on 16-bit range-checks (checking if a value of a field element is between 0 and 2
16). For example, most of the u32 operations need to perform between two and four 16-bit range-checks per operation. Similarly, operations involving memory (e.g. load and store) require two 16-bit range-checks per operation.


## 8-bit range checks

First, let's define a construction for the simplest possible 8-bit range-check. This can be done with a simple column as illustrated below.


| v |
|---|
| 0 |
| 1 |
| ... |
| 255 |

The constraints we enforce on this column:

* the value in first row must 0 and last must be 255
* the value in next row is equal or increment by 1 from current row

Denoting v as the value of column v in the current row, and v′ as the value of column v in the next row, we can enforce the last condition as follows:

\\[  (v - v') \cdot (v - v' - 1) = 0 \\]


Now lets make use of LogUp lookup argument by adding another column b which will keep a running sum that is the logarithmic derivative of the product of values in the v column. The transition constraint for b would look as follows:

\\[  b' = b + \frac{m} {\alpha -v} \\]

where m is the repeating times of v in the column.

| m | v |
|--- |---|
| 100 | 0 |
| 2 | 1 |
| 3 | ... |
| 1 | 255 |

Using these two columns we can check if some other column in the execution trace is a permutation of values in v. Let's call this other column x. We can compute the logarithmic derivative for x as a running sum in the same way as we compute it for v. Then, we can check that the last value in b is the same as the final value for the running sum of x.

* Additional Column in our Stark

RANGE\_CHECK: \\( v \\)

COUNTER: \\( 0..N \\)

FREQUENCIES: \\( m_i, i \in [0, N] \\)

Then we apply the Lookup scheme on the above 3 columns.
