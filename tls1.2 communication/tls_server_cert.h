const char ca_cert_buf[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDqzCCApOgAwIBAgIUeToCxiHLKtsmXtgK+S8FzhecyVwwDQYJKoZIhvcNAQEL\r\n"
  "BQAwZTELMAkGA1UEBhMCSEsxEjAQBgNVBAgMCUhvbmcgS29uZzESMBAGA1UEBwwJ\r\n"
  "SG9uZyBLb25nMQ4wDAYDVQQKDAVDaXR5VTELMAkGA1UECwwCQ1MxETAPBgNVBAMM\r\n"
  "CENpdHlVX0NTMB4XDTIxMDcyNDE1MjYzMloXDTIxMDgyMzE1MjYzMlowZTELMAkG\r\n"
  "A1UEBhMCSEsxEjAQBgNVBAgMCUhvbmcgS29uZzESMBAGA1UEBwwJSG9uZyBLb25n\r\n"
  "MQ4wDAYDVQQKDAVDaXR5VTELMAkGA1UECwwCQ1MxETAPBgNVBAMMCENpdHlVX0NT\r\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvYoXzLMEGlXq6q4WVYpm\r\n"
  "XlnxJpMgr46qhbeD1CTwA5PfEUARZgX3xsTrCP2YFecgFdajcfY+BTuGr3TRRYA1\r\n"
  "kY93FZqgVZx55vpz3oPZwDoCJLONF1yAClq4Z6rbRmH7UtAAEIB0PdZBuKW7W7Mj\r\n"
  "cKnreDeLBOfgsd+HlonmWxu8LeQxKi8JcmmlntcN8BMOyrzC6BFWztgwoRWid4iY\r\n"
  "AGnfBtFLfzElGv9WWFhv/3drCa/wdlppaugyihSHx0KZXb3WZBIGdlIHnG1P8C6O\r\n"
  "/1SCTvd4sgWQ6VL3zXnBpSKdBsS2ZkaG+vEwPVlF7JkQ1NQXgD1i4McjEcBmI0NC\r\n"
  "YQIDAQABo1MwUTAdBgNVHQ4EFgQUG4OOFzNVSML6oxz3edMVOmvm45EwHwYDVR0j\r\n"
  "BBgwFoAUG4OOFzNVSML6oxz3edMVOmvm45EwDwYDVR0TAQH/BAUwAwEB/zANBgkq\r\n"
  "hkiG9w0BAQsFAAOCAQEADqu0p/5z/wrd4wTL0mfnsLUw+u1JAMMM0EIC2MDdTVdL\r\n"
  "p6l5MxXDn6vZ2ApWNombMtUzoZEUquUt3npHR50Fa/apv7mXI6fqifUDTUKXfmMH\r\n"
  "q3x0Bpt1ujsWWaI8IyOaFxlBs21vaKBTRdTYweZ602/NdBMDdD3Q+UQgxiByO+3X\r\n"
  "MkpfzDSysOu1iuea4ZEgoc4+7l6xqR/9Guc5AGPsJxiLseFHsJpVHFu2fYUcaS3O\r\n"
  "WpMRhtXrju72uVtHfAHoHnXkndsMB44WHghXtOkwxVZtfUCC9D52ZThWJdmyAjoi\r\n"
  "7oHgwaiKrlgP6PUhGVXv5EdHXw1+ULxUbbGKfJgpXA==\r\n"
  "-----END CERTIFICATE-----\r\n";

const char server_cert_buf[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDrTCCApWgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCSEsx\r\n"
  "EjAQBgNVBAgMCUhvbmcgS29uZzESMBAGA1UEBwwJSG9uZyBLb25nMQ4wDAYDVQQK\r\n"
  "DAVDaXR5VTELMAkGA1UECwwCQ1MxETAPBgNVBAMMCENpdHlVX0NTMB4XDTIxMDcy\r\n"
  "NDE2MDMxOVoXDTIyMDcyNDE2MDMxOVowUTELMAkGA1UEBhMCSEsxEjAQBgNVBAgM\r\n"
  "CUhvbmcgS29uZzEOMAwGA1UECgwFQ2l0eVUxCzAJBgNVBAsMAkNTMREwDwYDVQQD\r\n"
  "DAhDaXR5VV9DUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPpDNuvV\r\n"
  "VC8XY9WfmwmtlRDNCDOvvNJ/6svOqurASP4ZL5DWvZZxN1WiIv5tR17hPj9h70Aj\r\n"
  "x5Ttah+anac6q3a5tTZXDlF4LnxjQxF7ZSYim+03aCt7RtwsLSOCz5BFaqt3Ubhv\r\n"
  "nfqnxh+V+SnbrbgMyHyRE7viFQlpghsd/1Y6ZKK+imwfHaFX9FLNR2AXfTrfJVqz\r\n"
  "tj03NkqeYQaa1jV0eiGf2Aq6M12JjLE1E1vkvPk30sH1bZ4obiurTbYY3hYUyYK2\r\n"
  "EkzGPQW+f1HEhNGoYZEi4XIDA59WUVGGeQfp8bxq+j6ST3LFv2ofMVuWUT4VFYHs\r\n"
  "4KU4odokaaRzK+UCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYd\r\n"
  "T3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFPH35AH55UAo\r\n"
  "DvkzM7tPTbksiK2aMB8GA1UdIwQYMBaAFBuDjhczVUjC+qMc93nTFTpr5uORMA0G\r\n"
  "CSqGSIb3DQEBCwUAA4IBAQCdf3ELik2JS94V56RzkLOd7FU0XUl0unvKNeqW15vX\r\n"
  "wYnkyLqYfezosQkuwHz8iTAEhwErNQqsiaR5basVROvcqKDQxGicWBizvtWQwR3Q\r\n"
  "xkEZwiqj98g0xzADHH/0HD5JDTe0g1j2wQmozbdRl3arXnp2L0v0i3aZHRPgoFfq\r\n"
  "ioeEgvJyxoOuYbuki0GInCDIZjJHYB7zG6oTSSyFYMyDQE1G5YEkTtjE0NfU06Z2\r\n"
  "2CJokp2COFOzldNQ5Td+aoX7qgenuoBlkKT8QJ11jTzsboOPYRaQpQP8I5gsJGf2\r\n"
  "jmvq7U2IIQy3+8je+RI9+BsD2KW85dBgSogSPRiQ0BHz\r\n"
  "-----END CERTIFICATE-----\r\n";

const char server_rsa_key_buf[] =
  "-----BEGIN RSA PRIVATE KEY-----\r\n"
  "MIIEpQIBAAKCAQEA+kM269VULxdj1Z+bCa2VEM0IM6+80n/qy86q6sBI/hkvkNa9\r\n"
  "lnE3VaIi/m1HXuE+P2HvQCPHlO1qH5qdpzqrdrm1NlcOUXgufGNDEXtlJiKb7Tdo\r\n"
  "K3tG3CwtI4LPkEVqq3dRuG+d+qfGH5X5KdutuAzIfJETu+IVCWmCGx3/Vjpkor6K\r\n"
  "bB8doVf0Us1HYBd9Ot8lWrO2PTc2Sp5hBprWNXR6IZ/YCrozXYmMsTUTW+S8+TfS\r\n"
  "wfVtnihuK6tNthjeFhTJgrYSTMY9Bb5/UcSE0ahhkSLhcgMDn1ZRUYZ5B+nxvGr6\r\n"
  "PpJPcsW/ah8xW5ZRPhUVgezgpTih2iRppHMr5QIDAQABAoIBAQC8AtD43XxwIF9V\r\n"
  "NqHP5IMvawk1Y1o0vfrUAEAxOiHcG2m7o0gtBIMwpy0o/Un4Armz/kwyYG7o+G+Y\r\n"
  "rJyx7IayHBQCbeaI2AP8WMojERPNUYTY8p4kxGlYsSt8GSL8XNolVO+k4t3JWE+k\r\n"
  "nRPiGXJp6diYlJlBtjhdqNEgtCmGSb3Of3OIJRdS8VLDhYKlocuE49vqXB1dTMqU\r\n"
  "BRNySS8Cpbgd0tFkX2DPAjAdUVU+c24pt6lVTHvoZJjXP91NWQ1K8yhMbrIVWdAv\r\n"
  "ipc9HyMEsWk6Bz+NhvCLFxhPMcDeLpnpGoGK7hkmwk+2FZ0A2MDVrCj0/wI8FqdL\r\n"
  "wytFsbaBAoGBAP2O75tX/U9fLm8dCsZUchpD39R64cfN4eBzbap1ukUfuRgsxbYy\r\n"
  "TNTC+tYhx9rfxRy2ZHlSHyezM2rXZ70UyIoOmd02WQZE/MKcWCFsli4ASKXUBTff\r\n"
  "asV9Yd7rDvrFuHvI7YnvWe5qp70cbQvIl6bmJSpQLAoj3Iw6N3Qb9KCFAoGBAPys\r\n"
  "J2YhNKgmlz4rV/mKCNPGpmDp7YWKypdQeL7OKpCzdOS+QdIRU77FzVtQ3QC/LGiV\r\n"
  "XTxtw2nLnI6W7yMPEGl43/hJD9C6sZwDu/KGpV8sp7NmzQJUhmsT0bTirGH6gSi1\r\n"
  "RnHjSi6PdY0qePDagWjqUfqhieSdy/DB+Z6uOOvhAoGBAMQ7evSehEyJPUaBE3Wq\r\n"
  "pSPuo6ut7k7T55vtuVHTCvW0N2ueOuVmyE9hFv/h5OpfhA1Umy3JgJMY/RIS4xZS\r\n"
  "n2E5K5soFH3lpjh3Bz3W6+NuFMtB60fygI+XGceL42vw2XXzauL1eoQpxud0uHAG\r\n"
  "LlfchabZpTuzxVxBMemKOSiBAoGAOfVfYDzzsDKR9M/KcVIpbjKeDZL7SeupRwZN\r\n"
  "fC8ccm7HvISr4nzZAeSrk2u8FiTEEgVZCrh+37C167tRhXA6KodwkKppt05r2Ua+\r\n"
  "AQbDvk4m9a76DbPH1Z4JN33bXuowYF8clpk1dfKwWz5H2a+1iZReU6hkUg2kL0i/\r\n"
  "cpeyNOECgYEAnCBchm72Y1XeUWVfsBtS2OMf7Fvt+oBm8gNaYnZmim0+Fb01yM5z\r\n"
  "unve59+XXXztSdiRZWI+E2WWftwxpR7N9hSq7rd+kmPppHNb72x/dsqw8HlgrOBx\r\n"
  "PI73iiCx1e9MxHxSnzzYeZVb/H/AYN5S4BFV92sXvL6uQWjSxhgUSJc=\r\n"
  "-----END RSA PRIVATE KEY-----\r\n";
