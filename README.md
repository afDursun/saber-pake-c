# Saber-PAKE-C
In the KEM category, the CRYSTALS-KYBER algorithm was announced as the standard algorithm by NIST. This repository is the PAKE version of Kyber.  SABER is the 3rd round lattice-based candidate algorithm in the standardization process initiated for NIST public-key cryptosystems. This repository is the PAKE version of Saber. 

cycles/ticks data of Saber-PAKE parameter sets

| Algorithm | LightSaber          |  Saber           | FireSaber          |
|:---------:|:----------:|:-------:|:-------:|:-------:|:---------:|:-------:|
|  Process  |   Median   | Average |  Median | Average |   Median  | Average |
|     c0    |   83 991   | 105 451 | 146 118 | 162 673 |  232 836  | 232 836 |
|     s0    |   94 458   | 100 739 | 162 489 | 170 159 |  255 237  | 278 094 |
|     c1    |   138 936  | 145 535 | 243 192 | 250 179 |  348 654  | 371 197 |
|     s1    |   41 802   |  44 412 |  59 391 |  63 862 |   80 820  |  86 409 |


Saber provides 3 different security categories. (LightSaber 128-bit; Saber 192-bit; FireSaber 256-bit). These security levels are provided by the SABER_L variable in the "SABER_params.h" file.

```c
#define SABER_L 2 /* LightSaber */
#define SABER_L 3 /* Saber */
#define SABER_L 4 /* FireSaber */
```

#### Test

```c
make saber_pake_test
```


#### Speed-Test

```c
make saber_pake_speed
```


## Acknowledgment

- This research was partially supported by TUBITAK under Grant No. 121R006
