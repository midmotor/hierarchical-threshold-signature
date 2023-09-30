# hierarchical-threshold-signature

he results of the tests performed on a computer with i7-1165g7 @ 2.80ghz and 16gb ram are as follows:

| Threshold | Number of Participants | Algorithm (Curve) | Time (ms) |
|-----------|------------------------|--------------------|------------|
| 4         | 5                      | Tassa (25519)      | 8.996      |
| 4         | 5                      | Plain (25519)      | 10.104     |
| 4         | 5                      | Our (25519)        | 6.498      |
| 4         | 7                      | Tassa (25519)      | 15.952     |
| 4         | 7                      | Plain (25519)      | 17.139     |
| 4         | 7                      | Our (25519)        | 13.280     |
| 4         | 10                     | Tassa (25519)      | 29.006     |
| 4         | 10                     | Plain (25519)      | 32.196     |
| 4         | 10                     | Our (25519)        | 25.768     |
| 4         | 5                      | Tassa (P256)       | 59.721     |
| 4         | 5                      | Plain (P256)       | 63.154     |
| 4         | 5                      | Our (P256)         | 40.724     |
| 4         | 7                      | Tassa (P256)       | 104.652    |
| 4         | 7                      | Plain (P256)       | 113.963    |
| 4         | 7                      | Our (P256)         | 89.735     |
| 4         | 10                     | Tassa (P256)       | 197.754    |
| 4         | 10                     | Plain (P256)       | 216.556    |
| 4         | 10                     | Our (P256)         | 172.907    |

