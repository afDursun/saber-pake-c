# Saber-PAKE-C
SABER is the 3rd round lattice-based candidate algorithm in the standardization process initiated for NIST public-key cryptosystems. This repository is the PAKE version of Saber. 

## Saber-PAKE's Performance Data
<br/>
<i>cycles/ticks data of Saber-PAKE parameter sets:</i>
<table>
<thead>
  <tr>
    <th>Algorithm</th>
    <th colspan="2">LightSaber</th>
    <th colspan="2">Saber</th>
    <th colspan="2">FireSaber</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Process</td>
    <td>Median</td>
    <td>Average</td>
    <td>Median</td>
    <td>Average</td>
    <td>Median</td>
    <td>Average</td>
  </tr>
  <tr>
    <td>c0</td>
    <td>83 991</td>
    <td>105 451</td>
    <td>146 118</td>
    <td>162 673</td>
    <td>232 836</td>
    <td>232 836</td>
  </tr>
  <tr>
    <td>s0</td>
    <td>94 458</td>
    <td>100 739</td>
    <td>162 489</td>
    <td>170 159</td>
    <td>255 237</td>
    <td>278 094</td>
  </tr>
  <tr>
    <td>c1</td>
    <td>138 936</td>
    <td>145 535</td>
    <td>243 192</td>
    <td>250 179</td>
    <td>348 654</td>
    <td>371 197</td>
  </tr>
  <tr>
    <td>s1</td>
    <td>41 802</td>
    <td>44 412</td>
    <td>59 391</td>
    <td>63 862</td>
    <td>80 820</td>
    <td>86 409</td>
  </tr>
</tbody>
</table>

<br/>
<i>The average time data (µs) of Saber-PAKE parameter sets:</i>
<table>
<thead>
  <tr>
    <th>Process</th>
    <th>LightSaber</th>
    <th>Saber</th>
    <th>FireSaber</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>c0</td>
    <td>44.039</td>
    <td>67.939</td>
    <td>102.735</td>
  </tr>
  <tr>
    <td>s0</td>
    <td>42.077</td>
    <td>71.068</td>
    <td>116.139</td>
  </tr>
  <tr>
    <td>c1</td>
    <td>60.785</td>
    <td>104.488</td>
    <td>155.021</td>
  </tr>
  <tr>
    <td>s1</td>
    <td>18.555</td>
    <td>26.690</td>
    <td>36.093</td>
  </tr>
</tbody>
</table>


## How to run Saber-PAKE
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
