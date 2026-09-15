//
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

// dummyPEM is an invalid PEM block for syntax failure testing.
const dummyPEM = "-----BEGIN CERTIFICATE-----\nMIIC...dummy...\n-----END CERTIFICATE-----"

// invalidDERPEM contains valid PEM headers but malformed ASN.1 DER payload.
const invalidDERPEM = "-----BEGIN CERTIFICATE-----\nSGVsbG8gV29ybGQ=\n-----END CERTIFICATE-----"

// certPEMWithoutSN is a static self-signed certificate lacking a Subject SerialNumber.
const certPEMWithoutSN = `-----BEGIN CERTIFICATE-----
MIICozCCAYugAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0
IENlcnQwIBcNMDAwMTAxMDAwMDAwWhgPMjA5OTEyMzEyMzU5NTlaMBQxEjAQBgNV
BAMMCVRlc3QgQ2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKKx
diiNsuzzmKb4hRbW8akrxSlc0efFQLbbI5RZon/ONSVG2tCXwMrOlU5RefbvdR9F
3RJUl7dI9bv5aSRwRrb15eIlSJsQeev1LUycYMmWU9fopbOZRXeSulwcNORE/nmc
I2jlpxDfLJruOweAFaRdgq0HbIpa5ozAVNS8JUp3Wsl4EE3wcqQ7oNDt3Aans/kt
CTUODHj7/hEIsc5T9gwZq5QsewaKqRv+GFX3IQLHQO4MuIvcJGhizffBxeWPtqVJ
eLEvbJXGvBv8xp4n7Z1wHALzFIHq4K/MetnS/x3cS77yXTFbVo2gkngR1Zx/oCBY
r5Bed0FM43s+KbpC6RcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAX3AwE/g78rfb
jtTHpThNm5xwAoptEhUNYqqWUW6/Iwx3ETKZ8p/cHasvfG01xJfcsWRkwROPpKc8
gvY1+lk1KpFRoeT9ODSN2xIktz0b0leh+eFMF2V1U+1hMQ7myAmN4t4moq3pIjP+
Qqd3QPyivhX3+1z7eRGdy37Oe5eID0G6W1O7ZORYCpOD7CpE7ABHEgQ8X+K35DK8
Io1XnNdtFmZIghSoKJmrzADkRT1Es9TmvkaDP5mobijHzTToYYsb+9muQtoOWn7I
xnGnuIgUaUyyNSzuD1n6VjIqaBbN2EZ2VwubZ7UEp1qvNCMLM57qRXJ+gcnU+i7T
38c+FhXyfg==
-----END CERTIFICATE-----`

// validTestCertPEMWithSN is a static self-signed certificate containing a valid Subject SerialNumber ("SN: 12345678").
const validTestCertPEMWithSN = `-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMRQwEgYDVQQDEwtUZXN0
IERldmljZTEVMBMGA1UEBRMMU046IDEyMzQ1Njc4MCAXDTAwMDEwMTAwMDAwMFoY
DzIwOTkxMjMxMjM1OTU5WjAtMRQwEgYDVQQDEwtUZXN0IERldmljZTEVMBMGA1UE
BRMMU046IDEyMzQ1Njc4MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
vijZSOSfNMQXYfP08XkazabVHQ7iWVTpfu0zRdUNBNPX1xuSMFjiwqa+Jh/bgTG+
jAdFH4/w0CbYdFoA+3DBdLiOwkXbh1CgoOu+77QTbHGO7BkoJ4Q4wYCDBuoIcg4p
BIkl/2wEiVa2y8zC4h8hZL/lbmOx+Tpx/9Ov+xWZFqMHIp84r5AQ8h0PZ3DEY/4i
Rpe0ejFw099gNTkc1y8M+AOyjj9pOXEXkfP+Ygiervl0l/J/JqBUOKkrxsIRJWvU
Se/jAwbeIObInxB7cqzo/5tKT1/c7PoOIj+B6fYPk/V+EKVaHpYQ1YuEcTRY3XD9
xtGod0/QmJgp/LbkuCCa/wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUNfRxX519AXIz2aXn/u0HHqJCBXgwDQYJKoZI
hvcNAQELBQADggEBABkVSr2A1+WAKkxNmv/ltUSACDbv5tR8YxsBMISdFunzlXe2
Dm8baFYKUDpRoNeK2KD5YjhlgpzakLsxveAZ0eSUMMiuKdxkEWXhRsC2tsjOqBPE
HAXjdQwDPh8fwPs1Pw35RziZU9mETP9Y92oO053V0rfg+egY2y8/2dfR8hDwGEf/
fOu8Jkb4Stp+FW2aPlkX/xubK6ofd9iCjQpKpE+H+12KJAWV6oe6tKK6XdIIOfxo
IFS6Qn5d8FPJgNW5QiJuuDA0Xf2NxhjLz0WV1FXumRyJoygBLJe9X14m8MA0apku
ecXtluwn/ZqV8GnkqRnd5BYOOv6ZAUxhgeN0Ym8=
-----END CERTIFICATE-----`

// testCertPEMWithDiffSN is a static self-signed certificate containing a different Subject SerialNumber ("SN: 87654321").
const testCertPEMWithDiffSN = `-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMRQwEgYDVQQDEwtUZXN0
IERldmljZTEVMBMGA1UEBRMMU046IDg3NjU0MzIxMCAXDTAwMDEwMTAwMDAwMFoY
DzIwOTkxMjMxMjM1OTU5WjAtMRQwEgYDVQQDEwtUZXN0IERldmljZTEVMBMGA1UE
BRMMU046IDg3NjU0MzIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
schaMCG+JHJwmz3NHyWFF6UdOnNEd50x1INwdMWJyf7WlXZnBWFR8YqdXVsfE7xs
MBnPDIW5B8DlQiCPfxLG0iLEK1bK31ViJbAz5z6wtorFxlcPSI2Fyb9dK2RDDZb/
0tpS+4imZVn7gaqFIFZ0xL6W1QBOo08tsLbHG6fNYMzecFLCoVTtsQX+OmwsqbW5
mUnNQGwW8lVfmKhfbXnDD5fb9l3iyhP9JHfS7TB0J+nL1g9i3D7WDgxiAnPdYO0x
MNByPNdINWFeKepB5h17gHEEDBB/XO/aiuYiOmYoqZnMq2KUOoHyxgg5cewHD++P
ibyExmVaOGovrmlzFV00qQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUGVM6hdr8GJcvHgbKInZsSjxsROMwDQYJKoZI
hvcNAQELBQADggEBADP+yg8c951bFfEkVGn3jFMpT/EmNBpejJ64B2K7zqu1JKI0
yEUxRfOORNSC6iS04AOwLrdL1fhqIL/gl3JxmOfM/mdgiix5wr67O+08jsshhzd2
1L0QkJ+cqPokvnHO/lqZryvklmPRwxCmltk9Pha0voKXwY910Q5v1oQFt7sUvtLs
h3Y+rctL4Ec4vkgBKpuxDDw0HkYKBsmKGgtIzBRRoceFZT39IZsY2dEQ2QFJRWs+
TFm4Lk739nkQOBveB6H3h+2ptroGW+/72yxKc/KOOD9SU+1OiDKGC9xNG9C7mhRv
JZWJTMNtECfShBl04jmISkaMwKhreEtYq/qiBpQ=
-----END CERTIFICATE-----`
