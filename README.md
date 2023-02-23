# Saber-PAKE-C
In the KEM category, the CRYSTALS-KYBER algorithm was announced as the standard algorithm by NIST. This repository is the PAKE version of Kyber.  SABER is the 3rd round lattice-based candidate algorithm in the standardization process initiated for NIST public-key cryptosystems. This repository is the PAKE version of Saber. 

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
