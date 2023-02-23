# Saber-PAKE-C
In the KEM category, the CRYSTALS-KYBER algorithm was announced as the standard algorithm by NIST. This repository is the PAKE version of Kyber.  SABER is the 3rd round lattice-based candidate algorithm in the standardization process initiated for NIST public-key cryptosystems. This repository is the PAKE version of Saber. 

cycles/ticks data of Saber-PAKE parameter sets

<table>
    <thead>
        <tr>
            <th>Layer 1</th>
            <th>Layer 2</th>
            <th>Layer 3</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan=4>L1 Name</td>
            <td rowspan=2>L2 Name A</td>
            <td>L3 Name A</td>
        </tr>
        <tr>
            <td>L3 Name B</td>
        </tr>
        <tr>
            <td rowspan=2>L2 Name B</td>
            <td>L3 Name C</td>
        </tr>
        <tr>
            <td>L3 Name D</td>
        </tr>
    </tbody>
</table>


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
