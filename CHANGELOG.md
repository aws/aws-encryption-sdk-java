# Changelog

## [3.0.2](https://github.com/aws/aws-encryption-sdk-java/compare/v3.0.1...v3.0.2) (2025-06-04)

### Fixes

* **AwsCrypto:** remove pre-mature Deprecation notices ([#2118](https://github.com/aws/aws-encryption-sdk-java/issues/2118)) ([4a19b04](https://github.com/aws/aws-encryption-sdk-java/commit/4a19b041a592e299f02d26a3625c5b5bc810897e))
* do not truncate encrypted streams when offset is greater than zero ([#2113](https://github.com/aws/aws-encryption-sdk-java/issues/2113)) ([adb0a42](https://github.com/aws/aws-encryption-sdk-java/commit/adb0a42dd23946b47d5486377fc2b560ebb18b0f))
* guard against null version and change property name to avoid conflicts ([#2116](https://github.com/aws/aws-encryption-sdk-java/issues/2116)) ([313caa7](https://github.com/aws/aws-encryption-sdk-java/commit/313caa7d24f86c875448dafd633cc74dc6d619c7))

### Maintenance

* add a test for offset against BlockEncryptionHandler ([#2115](https://github.com/aws/aws-encryption-sdk-java/issues/2115)) ([08cf1a3](https://github.com/aws/aws-encryption-sdk-java/commit/08cf1a333727f938f0a9d01b6605e38a89f6d099))
* bump to latest mpl ([#2046](https://github.com/aws/aws-encryption-sdk-java/issues/2046)) ([6dd2d12](https://github.com/aws/aws-encryption-sdk-java/commit/6dd2d128c96b4936c169966d911a19e63c976153))
* **cfn:** Sonatype Migration to User Tokens; updated policies for CI project ([#2043](https://github.com/aws/aws-encryption-sdk-java/issues/2043)) ([7cfe049](https://github.com/aws/aws-encryption-sdk-java/commit/7cfe049eeadc6c2c6d5eafa36f2ecd6e9f855302))
* **deps-dev:** bump commons-io:commons-io from 2.11.0 to 2.14.0 ([#2047](https://github.com/aws/aws-encryption-sdk-java/issues/2047)) ([1695a39](https://github.com/aws/aws-encryption-sdk-java/commit/1695a395692c0a42fd9149d4b1b7bc66df24d6d8))
* **examples:** Shared cache across Hierarchical Keyrings ([#2045](https://github.com/aws/aws-encryption-sdk-java/issues/2045)) ([fd00cd0](https://github.com/aws/aws-encryption-sdk-java/commit/fd00cd0e08f39a3ace414472a99f57b92e51be14))
* fix semantic release installation ([#2119](https://github.com/aws/aws-encryption-sdk-java/issues/2119)) ([0586279](https://github.com/aws/aws-encryption-sdk-java/commit/0586279c7842b9680aaa7080ddca55f1ff3e6707))
* **JavaDocs:** detail thread saftey of SDK Client Builders ([#2048](https://github.com/aws/aws-encryption-sdk-java/issues/2048)) ([86d5b62](https://github.com/aws/aws-encryption-sdk-java/commit/86d5b6275782eef2690823dbc7000f9aa2153a94))
* move release to Nexus Central ([#2117](https://github.com/aws/aws-encryption-sdk-java/issues/2117)) ([9e91dad](https://github.com/aws/aws-encryption-sdk-java/commit/9e91dade73f3b7fd165312e123cdfbe7dbd44483))

## [3.0.1](https://github.com/aws/aws-encryption-sdk-java/compare/v3.0.0...v3.0.1) (2024-06-12)

### Fixes

* Add Locale.ROOT to String uppercase conversions ([#1880](https://github.com/aws/aws-encryption-sdk-java/issues/1880)) ([9a9950e](https://github.com/aws/aws-encryption-sdk-java/commit/9a9950e880a137ed75b6c9329cbb77cbcdae7ef8)), closes [#1879](https://github.com/aws/aws-encryption-sdk-java/issues/1879)
* Update DecryptionMaterials code to support legacy custom CMMs ([#2037](https://github.com/aws/aws-encryption-sdk-java/issues/2037)) ([8807d79](https://github.com/aws/aws-encryption-sdk-java/commit/8807d79614394ce5a05a4f356e868470aa0b0f78))

### Maintenance

* deprecate getMasterKeyIds() in CryptoResult ([#1976](https://github.com/aws/aws-encryption-sdk-java/issues/1976)) ([1890ebb](https://github.com/aws/aws-encryption-sdk-java/commit/1890ebbd1baf40906f819a6b93ded8f936e20b50))
* **deps:** bump bcprov-jdk18on from 1.77 to 1.78.1 ([#2032](https://github.com/aws/aws-encryption-sdk-java/issues/2032)) ([713ca11](https://github.com/aws/aws-encryption-sdk-java/commit/713ca11a3f3eaf6d8b8926bf29340d30cda35b4b))
* **deps:** udpate org.bouncycastle to bcprov-jdk18on ([#1891](https://github.com/aws/aws-encryption-sdk-java/issues/1891)) ([32a92a9](https://github.com/aws/aws-encryption-sdk-java/commit/32a92a9333858cad1c40cebbc5cafc4637a81504))
* **deps:** update dependencies ([#1973](https://github.com/aws/aws-encryption-sdk-java/issues/1973)) ([800bd01](https://github.com/aws/aws-encryption-sdk-java/commit/800bd0137c53f58bae2588945dab143a4c760224))
* **Examples:** Customize KMS Client ([#2001](https://github.com/aws/aws-encryption-sdk-java/issues/2001)) ([e94ee85](https://github.com/aws/aws-encryption-sdk-java/commit/e94ee8538501f270138feab0a6138bed7ce640ea))
* fix release script ([#1912](https://github.com/aws/aws-encryption-sdk-java/issues/1912)) ([57e8a0b](https://github.com/aws/aws-encryption-sdk-java/commit/57e8a0b603c542e708aab5d04e13c2c314ec6aa5))
* **README:** update README.md ([#1940](https://github.com/aws/aws-encryption-sdk-java/issues/1940)) ([7a0899e](https://github.com/aws/aws-encryption-sdk-java/commit/7a0899e969b7b03ed73851fad44664d59d6b0bb5))
* update node version in version step ([#1959](https://github.com/aws/aws-encryption-sdk-java/issues/1959)) ([905385d](https://github.com/aws/aws-encryption-sdk-java/commit/905385d790011e2402543c6eddef400350b1229d))
* Update SUPPORT_POLICY.rst ([#1924](https://github.com/aws/aws-encryption-sdk-java/issues/1924)) ([57e40b5](https://github.com/aws/aws-encryption-sdk-java/commit/57e40b5788c80811bc3de972a48cb5b36940729d))

## [3.0.0](https://github.com/aws/aws-encryption-sdk-java/compare/v2.4.1...v3.0.0) (2023-12-06)


### ⚠ BREAKING CHANGES

* This feature update includes a breaking change that requires AWS SDK v2 Java as a hard dependency.

### Features

* Integrate ESDK-Java with AWS Cryptographic Material Providers Library (MPL) for Keyring and CMM Support. ([#1864](https://github.com/aws/aws-encryption-sdk-java/issues/1864)) ([9297e1b](https://github.com/aws/aws-encryption-sdk-java/commit/9297e1bad3860301bcf52b73466ec4b762e4f817))


### Maintenance

* **CFN:** remove unused policy ([#1862](https://github.com/aws/aws-encryption-sdk-java/issues/1862)) ([43e078a](https://github.com/aws/aws-encryption-sdk-java/commit/43e078ae1a99c751dc59a354fbc2c7b70b4afd82))
* **CFN:** update CFN stack to add managed policies to ci and release role ([#1856](https://github.com/aws/aws-encryption-sdk-java/issues/1856)) ([64c970f](https://github.com/aws/aws-encryption-sdk-java/commit/64c970f11ac7e14998c8939f937feeb48eee6c66))
* **deps:** bump org.apache.commons:commons-lang3 from 3.12.0 to 3.13.0 ([#1717](https://github.com/aws/aws-encryption-sdk-java/issues/1717)) ([ec41ae2](https://github.com/aws/aws-encryption-sdk-java/commit/ec41ae2d492699bfbbc7d9ac477105cd2dccbabd))
* fix release script ([#1796](https://github.com/aws/aws-encryption-sdk-java/issues/1796)) ([3617210](https://github.com/aws/aws-encryption-sdk-java/commit/3617210c1e60949aacd75f3c436b3b3010d0db71))
* fix release-ci ([#1883](https://github.com/aws/aws-encryption-sdk-java/issues/1883)) ([92f29d0](https://github.com/aws/aws-encryption-sdk-java/commit/92f29d0c47e09807c46201bb2c100f2172c51294))
* **tests:** update ESDK tests to replace sun.security.* API ([#1852](https://github.com/aws/aws-encryption-sdk-java/issues/1852)) ([ca4c763](https://github.com/aws/aws-encryption-sdk-java/commit/ca4c763fc8b6bf11df2914d37188aa5db5248042))
* update release process ([#1888](https://github.com/aws/aws-encryption-sdk-java/issues/1888)) ([f222462](https://github.com/aws/aws-encryption-sdk-java/commit/f2224626ed5bb6cdc90ee6d8f8eb61f07d3422ee))
* update the javadoc release script ([#1857](https://github.com/aws/aws-encryption-sdk-java/issues/1857)) ([1870a08](https://github.com/aws/aws-encryption-sdk-java/commit/1870a082358d59e32c60d74116d6f43c0efa466b))

## [2.4.1](https://github.com/aws/aws-encryption-sdk-java/compare/v2.4.0...v2.4.1) (2023-08-09)


### Fixes

* **ci:** Quote commit statement to prevent errant YAML parsing ([#581](https://github.com/aws/aws-encryption-sdk-java/issues/581)) ([2166f2d](https://github.com/aws/aws-encryption-sdk-java/commit/2166f2d49c2d80e90778b66e8189a23d55608265))
* Fix errors in the example code in README.md ([#1306](https://github.com/aws/aws-encryption-sdk-java/issues/1306)) ([b3f5b00](https://github.com/aws/aws-encryption-sdk-java/commit/b3f5b0021efeeee507c5bd3bcf2b8ec1720acfc4))
* NOTICE.txt ([#1617](https://github.com/aws/aws-encryption-sdk-java/issues/1617)) ([6dbf436](https://github.com/aws/aws-encryption-sdk-java/commit/6dbf436b026e289f0de7b484ff807b0c496b6ef3))


### Maintenance

* **ci:** add missing @Test annotation ([#1333](https://github.com/aws/aws-encryption-sdk-java/issues/1333)) ([3f289ac](https://github.com/aws/aws-encryption-sdk-java/commit/3f289ac6b8e2f29a2e1101747bf933027af6287f))
* **CommitmentPolicy:** Detail Commitment Policy on Enum ([#913](https://github.com/aws/aws-encryption-sdk-java/issues/913)) ([753bf7d](https://github.com/aws/aws-encryption-sdk-java/commit/753bf7dea8971bf5ca09b5512a6eb06da4eafcc7))
* **deps-dev:** bump junit-jupiter-api from 5.8.2 to 5.9.0 ([#1022](https://github.com/aws/aws-encryption-sdk-java/issues/1022)) ([3706959](https://github.com/aws/aws-encryption-sdk-java/commit/3706959c8730058ea0d567798ab21f4201e4be76))
* **deps-dev:** bump junit-jupiter-api from 5.9.0 to 5.9.1 ([#1073](https://github.com/aws/aws-encryption-sdk-java/issues/1073)) ([a85666c](https://github.com/aws/aws-encryption-sdk-java/commit/a85666c348ca8f329e588989f4154dedbce53486))
* **deps-dev:** bump junit-jupiter-api from 5.9.1 to 5.9.2 ([#1313](https://github.com/aws/aws-encryption-sdk-java/issues/1313)) ([1466784](https://github.com/aws/aws-encryption-sdk-java/commit/14667842311da250ad98a74e8143a44cda886823))
* **deps-dev:** bump junit-vintage-engine from 5.8.2 to 5.9.0 ([#1050](https://github.com/aws/aws-encryption-sdk-java/issues/1050)) ([4a1222c](https://github.com/aws/aws-encryption-sdk-java/commit/4a1222c8fb8beb64be98e9cad5a5db903e0679b8))
* **deps-dev:** bump junit-vintage-engine from 5.9.0 to 5.9.1 ([#1074](https://github.com/aws/aws-encryption-sdk-java/issues/1074)) ([55746cf](https://github.com/aws/aws-encryption-sdk-java/commit/55746cf2e86c34a04e3d8311e689de6171ed8681))
* **deps-dev:** bump junit-vintage-engine from 5.9.1 to 5.9.3 ([#1550](https://github.com/aws/aws-encryption-sdk-java/issues/1550)) ([14b6766](https://github.com/aws/aws-encryption-sdk-java/commit/14b6766b23c18ca59fd8309ca3d60d91ea977e91))
* **deps-dev:** bump mockito-core from 4.10.0 to 4.11.0 ([#1283](https://github.com/aws/aws-encryption-sdk-java/issues/1283)) ([5311392](https://github.com/aws/aws-encryption-sdk-java/commit/53113926a6af4f8537a705f21a654dd34c8a509b))
* **deps-dev:** bump mockito-core from 4.3.1 to 4.4.0 ([#625](https://github.com/aws/aws-encryption-sdk-java/issues/625)) ([3e6edf3](https://github.com/aws/aws-encryption-sdk-java/commit/3e6edf3de6e59c995b9ce7b7ef7164bbe24706a1))
* **deps-dev:** bump mockito-core from 4.4.0 to 4.6.1 ([#918](https://github.com/aws/aws-encryption-sdk-java/issues/918)) ([bf7978b](https://github.com/aws/aws-encryption-sdk-java/commit/bf7978b23e16b706686e33c9696ac17232e0ef78))
* **deps-dev:** bump mockito-core from 4.6.1 to 4.8.0 ([#1055](https://github.com/aws/aws-encryption-sdk-java/issues/1055)) ([d47e1de](https://github.com/aws/aws-encryption-sdk-java/commit/d47e1de49bab2d13dd146a67b988803b7f73303f))
* **deps-dev:** bump mockito-core from 4.8.0 to 4.8.1 ([#1147](https://github.com/aws/aws-encryption-sdk-java/issues/1147)) ([e2a0f52](https://github.com/aws/aws-encryption-sdk-java/commit/e2a0f52493bf1edaa8d6ca03a2e14a66273c3f03))
* **deps-dev:** bump mockito-core from 4.8.1 to 4.9.0 ([#1194](https://github.com/aws/aws-encryption-sdk-java/issues/1194)) ([28c2e71](https://github.com/aws/aws-encryption-sdk-java/commit/28c2e7101c1ba5581c43e3074bf932cce103cb55))
* **deps-dev:** bump mockito-core from 4.9.0 to 4.10.0 ([#1254](https://github.com/aws/aws-encryption-sdk-java/issues/1254)) ([07e2ed2](https://github.com/aws/aws-encryption-sdk-java/commit/07e2ed2a0c525429698f247cc880db730e745aca))
* **deps:** bump actions/checkout from 2 to 3 ([#558](https://github.com/aws/aws-encryption-sdk-java/issues/558)) ([6652268](https://github.com/aws/aws-encryption-sdk-java/commit/66522687d6e74791a33a29d3a70727c6a604cd33))
* **deps:** bump aws-actions/configure-aws-credentials from 1 to 2 ([#1437](https://github.com/aws/aws-encryption-sdk-java/issues/1437)) ([91a5811](https://github.com/aws/aws-encryption-sdk-java/commit/91a5811e4ef14b9abbf2e12d6d8f615ec6bb84a4))
* **deps:** bump aws-java-sdk from 1.12.162 to 1.12.186 ([#629](https://github.com/aws/aws-encryption-sdk-java/issues/629)) ([ec38abe](https://github.com/aws/aws-encryption-sdk-java/commit/ec38abe2aea13be02b5c0e666efb58d44ce65ff1))
* **deps:** bump aws-java-sdk from 1.12.186 to 1.12.256 ([#920](https://github.com/aws/aws-encryption-sdk-java/issues/920)) ([ef4126b](https://github.com/aws/aws-encryption-sdk-java/commit/ef4126b8b4384a4e4ba70db2bc89520dbe85030f))
* **deps:** bump aws-java-sdk from 1.12.256 to 1.12.299 ([#1047](https://github.com/aws/aws-encryption-sdk-java/issues/1047)) ([fdf0a6d](https://github.com/aws/aws-encryption-sdk-java/commit/fdf0a6d7338882e35f1a1297c203320817effce1))
* **deps:** bump aws-java-sdk from 1.12.299 to 1.12.301 ([#1053](https://github.com/aws/aws-encryption-sdk-java/issues/1053)) ([718b3a2](https://github.com/aws/aws-encryption-sdk-java/commit/718b3a2abc2678e998100c05a060358e45ae50cc))
* **deps:** bump aws-java-sdk from 1.12.301 to 1.12.303 ([#1059](https://github.com/aws/aws-encryption-sdk-java/issues/1059)) ([970e9db](https://github.com/aws/aws-encryption-sdk-java/commit/970e9db0689170ade369084c8cb66e2a16c54f33))
* **deps:** bump aws-java-sdk from 1.12.303 to 1.12.304 ([#1063](https://github.com/aws/aws-encryption-sdk-java/issues/1063)) ([e8471dc](https://github.com/aws/aws-encryption-sdk-java/commit/e8471dc57f6cfbd0ec79df31261dd9b541d53c42))
* **deps:** bump aws-java-sdk from 1.12.304 to 1.12.305 ([#1066](https://github.com/aws/aws-encryption-sdk-java/issues/1066)) ([5bc4b3b](https://github.com/aws/aws-encryption-sdk-java/commit/5bc4b3b5f18c6326bcb0cd4899aeb73b919a1e1c))
* **deps:** bump aws-java-sdk from 1.12.305 to 1.12.306 ([#1071](https://github.com/aws/aws-encryption-sdk-java/issues/1071)) ([93c8314](https://github.com/aws/aws-encryption-sdk-java/commit/93c8314117a7907bc6015385dcb42dc72129e179))
* **deps:** bump aws-java-sdk from 1.12.306 to 1.12.307 ([#1076](https://github.com/aws/aws-encryption-sdk-java/issues/1076)) ([88f85f4](https://github.com/aws/aws-encryption-sdk-java/commit/88f85f4427461041916000b1c50ccb8aaf1692df))
* **deps:** bump aws-java-sdk from 1.12.307 to 1.12.308 ([#1081](https://github.com/aws/aws-encryption-sdk-java/issues/1081)) ([53345b8](https://github.com/aws/aws-encryption-sdk-java/commit/53345b8979bd31f1ce7183621ec1cc2375095e87))
* **deps:** bump aws-java-sdk from 1.12.308 to 1.12.309 ([#1085](https://github.com/aws/aws-encryption-sdk-java/issues/1085)) ([658f9e9](https://github.com/aws/aws-encryption-sdk-java/commit/658f9e9e5d408a2b8df9ad00e373af4e5d0854ef))
* **deps:** bump aws-java-sdk from 1.12.309 to 1.12.318 ([#1121](https://github.com/aws/aws-encryption-sdk-java/issues/1121)) ([18443d4](https://github.com/aws/aws-encryption-sdk-java/commit/18443d47b416b34dc8f634107b0dfef86ca881c7))
* **deps:** bump aws-java-sdk from 1.12.318 to 1.12.319 ([#1124](https://github.com/aws/aws-encryption-sdk-java/issues/1124)) ([624c592](https://github.com/aws/aws-encryption-sdk-java/commit/624c592e76ae358b216381ec22b509a6b63dfbe0))
* **deps:** bump aws-java-sdk from 1.12.319 to 1.12.323 ([#1138](https://github.com/aws/aws-encryption-sdk-java/issues/1138)) ([74b3dd3](https://github.com/aws/aws-encryption-sdk-java/commit/74b3dd325f52818f249c40b54c119b8708c808d8))
* **deps:** bump aws-java-sdk from 1.12.323 to 1.12.335 ([#1173](https://github.com/aws/aws-encryption-sdk-java/issues/1173)) ([b8b0d53](https://github.com/aws/aws-encryption-sdk-java/commit/b8b0d5305ddf714105db1e258da25ad3973f2b13))
* **deps:** bump aws-java-sdk from 1.12.335 to 1.12.337 ([#1176](https://github.com/aws/aws-encryption-sdk-java/issues/1176)) ([fa92676](https://github.com/aws/aws-encryption-sdk-java/commit/fa92676118ec1d5f8db97de0521bc34f0bd5b0ff))
* **deps:** bump aws-java-sdk from 1.12.337 to 1.12.350 ([#1220](https://github.com/aws/aws-encryption-sdk-java/issues/1220)) ([35235a0](https://github.com/aws/aws-encryption-sdk-java/commit/35235a00b4ec12b9fae9a6ab76b8adb355a58ae3))
* **deps:** bump aws-java-sdk from 1.12.350 to 1.12.366 ([#1259](https://github.com/aws/aws-encryption-sdk-java/issues/1259)) ([456a4ad](https://github.com/aws/aws-encryption-sdk-java/commit/456a4addd8c665ac68af09fec5216c01bb684f29))
* **deps:** bump aws-java-sdk from 1.12.366 to 1.12.381 ([#1308](https://github.com/aws/aws-encryption-sdk-java/issues/1308)) ([80ed0a6](https://github.com/aws/aws-encryption-sdk-java/commit/80ed0a6f2277e1bf86b65fff55b073839f404d7e))
* **deps:** bump aws-java-sdk from 1.12.381 to 1.12.394 ([#1351](https://github.com/aws/aws-encryption-sdk-java/issues/1351)) ([0445b9e](https://github.com/aws/aws-encryption-sdk-java/commit/0445b9e8fc16193a7e7f0b6a09f8a08dbec75094))
* **deps:** bump BouncyCastle from 1.72 to 1.75 ([#1670](https://github.com/aws/aws-encryption-sdk-java/issues/1670)) ([61b6260](https://github.com/aws/aws-encryption-sdk-java/commit/61b6260e1df17507cd4cb01a8a7d08b05d8fd745))
* **deps:** bump jacoco-maven-plugin from 0.8.7 to 0.8.8 ([#655](https://github.com/aws/aws-encryption-sdk-java/issues/655)) ([802946a](https://github.com/aws/aws-encryption-sdk-java/commit/802946a172fb538ffeb080b8efd0442d9717cee0))
* **deps:** bump kms from 2.17.136 to 2.17.226 ([#916](https://github.com/aws/aws-encryption-sdk-java/issues/916)) ([6a4011e](https://github.com/aws/aws-encryption-sdk-java/commit/6a4011e7e36e5348f91c4a38d5ca7ef3f4792749))
* **deps:** bump kms from 2.17.226 to 2.17.259 ([#1020](https://github.com/aws/aws-encryption-sdk-java/issues/1020)) ([6fc33b7](https://github.com/aws/aws-encryption-sdk-java/commit/6fc33b7a937164897336b12108a4a6ae751c5130))
* **deps:** bump kms from 2.17.259 to 2.17.273 ([#1054](https://github.com/aws/aws-encryption-sdk-java/issues/1054)) ([d87cf16](https://github.com/aws/aws-encryption-sdk-java/commit/d87cf16813d8fe401c992cf03c8643a06723bae1))
* **deps:** bump kms from 2.17.273 to 2.17.274 ([#1058](https://github.com/aws/aws-encryption-sdk-java/issues/1058)) ([4ab03c4](https://github.com/aws/aws-encryption-sdk-java/commit/4ab03c494c0981e9130c283243b8f8fbd8fb182a))
* **deps:** bump kms from 2.17.274 to 2.17.275 ([#1062](https://github.com/aws/aws-encryption-sdk-java/issues/1062)) ([5a70da4](https://github.com/aws/aws-encryption-sdk-java/commit/5a70da4cb1c1c8496bdde602fc9da6cc1cf08742))
* **deps:** bump kms from 2.17.275 to 2.17.276 ([#1065](https://github.com/aws/aws-encryption-sdk-java/issues/1065)) ([a3d1fae](https://github.com/aws/aws-encryption-sdk-java/commit/a3d1fae210285f3d32123b4ef08c489b42f9ddf2))
* **deps:** bump kms from 2.17.276 to 2.17.277 ([#1070](https://github.com/aws/aws-encryption-sdk-java/issues/1070)) ([7ca5c11](https://github.com/aws/aws-encryption-sdk-java/commit/7ca5c11d4b18d79f83ec0ed88e9d32c5431cd8b1))
* **deps:** bump kms from 2.17.277 to 2.17.278 ([#1075](https://github.com/aws/aws-encryption-sdk-java/issues/1075)) ([cbac0a3](https://github.com/aws/aws-encryption-sdk-java/commit/cbac0a393ba08262fe4ca515608c2f8479464b98))
* **deps:** bump kms from 2.17.278 to 2.17.279 ([#1080](https://github.com/aws/aws-encryption-sdk-java/issues/1080)) ([558b2f4](https://github.com/aws/aws-encryption-sdk-java/commit/558b2f449c1d9904ff76615253c288ecd429f1eb))
* **deps:** bump kms from 2.17.279 to 2.17.280 ([#1086](https://github.com/aws/aws-encryption-sdk-java/issues/1086)) ([29774ad](https://github.com/aws/aws-encryption-sdk-java/commit/29774ade298282dcac668c3afb622e6ec06fe4ab))
* **deps:** bump kms from 2.17.280 to 2.17.288 ([#1118](https://github.com/aws/aws-encryption-sdk-java/issues/1118)) ([8d94a69](https://github.com/aws/aws-encryption-sdk-java/commit/8d94a6981838c5e01b3c1626c681e64991f35994))
* **deps:** bump kms from 2.17.288 to 2.17.289 ([#1122](https://github.com/aws/aws-encryption-sdk-java/issues/1122)) ([d09ff99](https://github.com/aws/aws-encryption-sdk-java/commit/d09ff99714f906b46b224a4747d1c6d96b682b91))
* **deps:** bump kms from 2.17.289 to 2.17.292 ([ff69200](https://github.com/aws/aws-encryption-sdk-java/commit/ff692006dc6ea7c5d19de6c2b93f7c1392abf95f))
* **deps:** bump kms from 2.17.292 to 2.18.8 ([#1167](https://github.com/aws/aws-encryption-sdk-java/issues/1167)) ([fa16a2d](https://github.com/aws/aws-encryption-sdk-java/commit/fa16a2d15876a91ac59d2c45efcb3ee6e7e2f68f))
* **deps:** bump kms from 2.18.12 to 2.18.38 ([#1252](https://github.com/aws/aws-encryption-sdk-java/issues/1252)) ([e35cf06](https://github.com/aws/aws-encryption-sdk-java/commit/e35cf06277cd4dea359ecabb96ec3a160b9a3c31))
* **deps:** bump kms from 2.18.8 to 2.18.12 ([#1177](https://github.com/aws/aws-encryption-sdk-java/issues/1177)) ([f514633](https://github.com/aws/aws-encryption-sdk-java/commit/f514633f91ecf2df39f90e0bbcd7469097ca79ca))
* **deps:** bump maven-compiler-plugin from 3.9.0 to 3.10.1 ([#582](https://github.com/aws/aws-encryption-sdk-java/issues/582)) ([9e24357](https://github.com/aws/aws-encryption-sdk-java/commit/9e243579269df1f3d08769abc8b11c3354e4400c))
* **deps:** bump maven-javadoc-plugin from 3.3.1 to 3.3.2 ([#525](https://github.com/aws/aws-encryption-sdk-java/issues/525)) ([8489bd6](https://github.com/aws/aws-encryption-sdk-java/commit/8489bd6d7accf7d48d2070873fe6daefad77ca8c))
* **deps:** bump maven-javadoc-plugin from 3.3.2 to 3.4.1 ([#998](https://github.com/aws/aws-encryption-sdk-java/issues/998)) ([44be313](https://github.com/aws/aws-encryption-sdk-java/commit/44be313eeb13236b376975290fb52a5583f21941))
* **deps:** bump maven-surefire-plugin from 2.22.2 to 3.1.2 ([#1632](https://github.com/aws/aws-encryption-sdk-java/issues/1632)) ([ea0a848](https://github.com/aws/aws-encryption-sdk-java/commit/ea0a848c1f2e3ad42f2be7d67add9b33cafa7f4f))
* **deps:** bump nexus-staging-maven-plugin from 1.6.12 to 1.6.13 ([#704](https://github.com/aws/aws-encryption-sdk-java/issues/704)) ([15fab9f](https://github.com/aws/aws-encryption-sdk-java/commit/15fab9fafc5ccc9e689775db3075690f9869e513))
* **deps:** bump software.amazon.awssdk:bom from 2.17.136 to 2.17.228 ([#925](https://github.com/aws/aws-encryption-sdk-java/issues/925)) ([ae52cef](https://github.com/aws/aws-encryption-sdk-java/commit/ae52cef6b55f753b2d6ca0909e30972ca59176d6))
* **deps:** bump software.amazon.awssdk:bom from 2.17.228 to 2.17.273 ([#1056](https://github.com/aws/aws-encryption-sdk-java/issues/1056)) ([e40651c](https://github.com/aws/aws-encryption-sdk-java/commit/e40651c24599ff505a0f9925063e486d5bf55af7))
* **deps:** bump software.amazon.awssdk:bom from 2.17.273 to 2.17.274 ([#1057](https://github.com/aws/aws-encryption-sdk-java/issues/1057)) ([35f38bd](https://github.com/aws/aws-encryption-sdk-java/commit/35f38bd85df2d919cdb40acb730380158d3fca86))
* **deps:** bump software.amazon.awssdk:bom from 2.17.274 to 2.17.275 ([#1061](https://github.com/aws/aws-encryption-sdk-java/issues/1061)) ([18c8172](https://github.com/aws/aws-encryption-sdk-java/commit/18c8172f83c63f539c4ebd2db29be694e79d6499))
* **deps:** bump software.amazon.awssdk:bom from 2.17.275 to 2.17.276 ([#1067](https://github.com/aws/aws-encryption-sdk-java/issues/1067)) ([efd340d](https://github.com/aws/aws-encryption-sdk-java/commit/efd340d713f7a1979d4d5f2f7e790a7ec15aabb1))
* **deps:** bump software.amazon.awssdk:bom from 2.17.276 to 2.17.277 ([#1069](https://github.com/aws/aws-encryption-sdk-java/issues/1069)) ([5721a81](https://github.com/aws/aws-encryption-sdk-java/commit/5721a8172fa62564530ec9d000372f0719269858))
* **deps:** bump software.amazon.awssdk:bom from 2.17.277 to 2.17.278 ([#1077](https://github.com/aws/aws-encryption-sdk-java/issues/1077)) ([49b867e](https://github.com/aws/aws-encryption-sdk-java/commit/49b867eea38e218906fa1467a896d4d1e800a1e2))
* **deps:** bump software.amazon.awssdk:bom from 2.17.278 to 2.17.280 ([#1084](https://github.com/aws/aws-encryption-sdk-java/issues/1084)) ([cb2a92f](https://github.com/aws/aws-encryption-sdk-java/commit/cb2a92f728a833270f8ca0c8199c2ff270718b78))
* **deps:** bump software.amazon.awssdk:bom from 2.17.280 to 2.17.288 ([#1116](https://github.com/aws/aws-encryption-sdk-java/issues/1116)) ([7ff4e14](https://github.com/aws/aws-encryption-sdk-java/commit/7ff4e14ff07156dd82c374af9ef16906b2e7d6a8))
* **deps:** bump software.amazon.awssdk:bom from 2.17.288 to 2.17.292 ([98236cd](https://github.com/aws/aws-encryption-sdk-java/commit/98236cd4ceb51d2dd3c0e62e08a1366a15a3f462))
* **deps:** bump software.amazon.awssdk:bom from 2.17.292 to 2.18.1 ([#1148](https://github.com/aws/aws-encryption-sdk-java/issues/1148)) ([f7f6088](https://github.com/aws/aws-encryption-sdk-java/commit/f7f6088285eefe1ba513ac7c4eeab1b966e96155))
* **deps:** bump software.amazon.awssdk:bom from 2.18.1 to 2.18.8 ([#1168](https://github.com/aws/aws-encryption-sdk-java/issues/1168)) ([12e5383](https://github.com/aws/aws-encryption-sdk-java/commit/12e53837dddd098cadeebf31e0f19124d6b4f93f))
* **deps:** bump software.amazon.awssdk:bom from 2.18.12 to 2.18.38 ([#1251](https://github.com/aws/aws-encryption-sdk-java/issues/1251)) ([6593b98](https://github.com/aws/aws-encryption-sdk-java/commit/6593b983c42b749b2ceed64901f81ca92f32d172))
* **deps:** bump software.amazon.awssdk:bom from 2.18.38 to 2.19.11 ([#1299](https://github.com/aws/aws-encryption-sdk-java/issues/1299)) ([cd08a3b](https://github.com/aws/aws-encryption-sdk-java/commit/cd08a3ba01ade863bd75f65dbcadb2c852b91b83))
* **deps:** bump software.amazon.awssdk:bom from 2.18.8 to 2.18.12 ([#1178](https://github.com/aws/aws-encryption-sdk-java/issues/1178)) ([03bc7bd](https://github.com/aws/aws-encryption-sdk-java/commit/03bc7bd08c8f50f170c754e2dd802cf538a01394))
* **deps:** bump software.amazon.awssdk:bom from 2.19.11 to 2.19.26 ([#1354](https://github.com/aws/aws-encryption-sdk-java/issues/1354)) ([7ee7f55](https://github.com/aws/aws-encryption-sdk-java/commit/7ee7f55691251c207f9667a0da899b98b4f07149))
* **deps:** bump software.amazon.awssdk:bom from 2.19.26 to 2.20.91 ([#1667](https://github.com/aws/aws-encryption-sdk-java/issues/1667)) ([2b5f92a](https://github.com/aws/aws-encryption-sdk-java/commit/2b5f92a68d3e5304ee0fda75541c03f797b8a78f))
* Detail AWS SDK v2 support ([#835](https://github.com/aws/aws-encryption-sdk-java/issues/835)) ([5705e1f](https://github.com/aws/aws-encryption-sdk-java/commit/5705e1f2aaa8def520b2ea73a7dd50c845cf6ed9))
* Fix re-run CI workflows ([#1219](https://github.com/aws/aws-encryption-sdk-java/issues/1219)) ([3bec521](https://github.com/aws/aws-encryption-sdk-java/commit/3bec521ba0bf6cb8a91c1a585d3b7b6a355d095c))
* remove mainline-1.x from dependabot ([#1120](https://github.com/aws/aws-encryption-sdk-java/issues/1120)) ([3956822](https://github.com/aws/aws-encryption-sdk-java/commit/3956822018126c03158cf7b6d9f8ea18ebee990a))
* Run CodeBuild CI from Github Actions ([#1213](https://github.com/aws/aws-encryption-sdk-java/issues/1213)) ([ba726b5](https://github.com/aws/aws-encryption-sdk-java/commit/ba726b5037cad31c94a1e1f4fbcd53786c446d2b))
* **SupportPolicy:** Mark 1.x End-of-Support ([#1026](https://github.com/aws/aws-encryption-sdk-java/issues/1026)) ([ff93eab](https://github.com/aws/aws-encryption-sdk-java/commit/ff93eab16c8059d0e6f11f0719cf5cb5e65050b9))
* Update `org.bouncycastle` to `bcprov-ext-jdk18on` ([#1572](https://github.com/aws/aws-encryption-sdk-java/issues/1572)) ([c56aff3](https://github.com/aws/aws-encryption-sdk-java/commit/c56aff30471899460a7821ae97e3869b22a24612))
* update node version in versioning cb step ([#1712](https://github.com/aws/aws-encryption-sdk-java/issues/1712)) ([a34e0ad](https://github.com/aws/aws-encryption-sdk-java/commit/a34e0add6f900575f399f332a44f573e6884a615))
* use correct signing key for release ([#928](https://github.com/aws/aws-encryption-sdk-java/issues/928)) ([86332e4](https://github.com/aws/aws-encryption-sdk-java/commit/86332e4b895bf0cdeef0570974e5d3707db0643c))
* use new signing keys for ci ([#840](https://github.com/aws/aws-encryption-sdk-java/issues/840)) ([6043417](https://github.com/aws/aws-encryption-sdk-java/commit/60434173026c3f6a6e268124bfebcf308d78cf2c))

## [2.4.0](https://github.com/aws/aws-encryption-sdk-java/compare/v2.3.3...v2.4.0) (2022-03-09)


### Features

* AWS SDK v2 support ([006cdc4](https://github.com/aws/aws-encryption-sdk-java/commit/006cdc4b6395536c8c1b317d85c252f4892d6172))


### Fixes

* Revert "AWS Encryption SDK 2.4.0 Release -- $(date +%Y-%m-%d)" ([7563a95](https://github.com/aws/aws-encryption-sdk-java/commit/7563a9536fdd0a637777df7659f15bfbb56f31cb))


### Maintenance

* Add back removed CiphertextHeaders.deserialize method ([#382](https://github.com/aws/aws-encryption-sdk-java/issues/382)) ([c1f3e63](https://github.com/aws/aws-encryption-sdk-java/commit/c1f3e637421c7d5d71a092fd4812aa435639c3da))
* add build to support uploading artifacts ([#379](https://github.com/aws/aws-encryption-sdk-java/issues/379)) ([69e7914](https://github.com/aws/aws-encryption-sdk-java/commit/69e7914d30e8c0ecea11aed7a924f77210677991))
* Add CODEOWNERS file ([#406](https://github.com/aws/aws-encryption-sdk-java/issues/406)) ([b9adf9f](https://github.com/aws/aws-encryption-sdk-java/commit/b9adf9fdb3177d80bd7c2ec5ddad86230f2b13f4))
* add javadoc update to batch build ([#376](https://github.com/aws/aws-encryption-sdk-java/issues/376)) ([d88190b](https://github.com/aws/aws-encryption-sdk-java/commit/d88190b810452c29c9e48892806bc7063a75800a))
* Adding semantic release config file ([#346](https://github.com/aws/aws-encryption-sdk-java/issues/346)) ([6201c1a](https://github.com/aws/aws-encryption-sdk-java/commit/6201c1accccd3dea2d991a1d579234842865540d))
* **ci:** change release vars ([#578](https://github.com/aws/aws-encryption-sdk-java/issues/578)) ([de99b56](https://github.com/aws/aws-encryption-sdk-java/commit/de99b563d1cd63551e284a0b9c71dad8dec53444))
* **deps-dev:** bump junit-jupiter-api from 5.7.2 to 5.8.0 ([#339](https://github.com/aws/aws-encryption-sdk-java/issues/339)) ([6dfaef9](https://github.com/aws/aws-encryption-sdk-java/commit/6dfaef907b5ec5a3ed0c8bb4e774792f683ef03d))
* **deps-dev:** bump junit-jupiter-api from 5.8.0 to 5.8.1 ([#347](https://github.com/aws/aws-encryption-sdk-java/issues/347)) ([7d3bb0a](https://github.com/aws/aws-encryption-sdk-java/commit/7d3bb0a976746bfb56c13136e876234ea64da581))
* **deps-dev:** bump junit-jupiter-api from 5.8.1 to 5.8.2 ([#427](https://github.com/aws/aws-encryption-sdk-java/issues/427)) ([7de569a](https://github.com/aws/aws-encryption-sdk-java/commit/7de569aa3766e2339a2c7bbf0bb3c474f75f99cd))
* **deps-dev:** bump junit-vintage-engine from 5.7.2 to 5.8.0 ([#337](https://github.com/aws/aws-encryption-sdk-java/issues/337)) ([2338b92](https://github.com/aws/aws-encryption-sdk-java/commit/2338b92358b655ee057ba15b4a6b4282988f8875))
* **deps-dev:** bump junit-vintage-engine from 5.8.0 to 5.8.1 ([#348](https://github.com/aws/aws-encryption-sdk-java/issues/348)) ([d0221cf](https://github.com/aws/aws-encryption-sdk-java/commit/d0221cf8367d7cf2e03ef94dc55f09e48ef9fa07))
* **deps-dev:** bump junit-vintage-engine from 5.8.1 to 5.8.2 ([#426](https://github.com/aws/aws-encryption-sdk-java/issues/426)) ([065ab94](https://github.com/aws/aws-encryption-sdk-java/commit/065ab94d7ca57d33fac8217cdcba4f046d7e910c))
* **deps-dev:** bump mockito-core from 3.12.3 to 3.12.4 ([#323](https://github.com/aws/aws-encryption-sdk-java/issues/323)) ([0208d0d](https://github.com/aws/aws-encryption-sdk-java/commit/0208d0d1a2309a26277f3793dc3e7ba6c13c1141))
* **deps-dev:** bump mockito-core from 4.0.0 to 4.1.0 ([#441](https://github.com/aws/aws-encryption-sdk-java/issues/441)) ([8dfda1a](https://github.com/aws/aws-encryption-sdk-java/commit/8dfda1ac4d28d82e069a91891743a524965a16e8))
* **deps-dev:** bump mockito-core from 4.1.0 to 4.2.0 ([#458](https://github.com/aws/aws-encryption-sdk-java/issues/458)) ([a1b1885](https://github.com/aws/aws-encryption-sdk-java/commit/a1b18851328a310deff388b11f0fbf691a4cfd2b))
* **deps-dev:** bump mockito-core from 4.2.0 to 4.3.1 ([#500](https://github.com/aws/aws-encryption-sdk-java/issues/500)) ([a709e69](https://github.com/aws/aws-encryption-sdk-java/commit/a709e69c3beca2824bc5f6c6529b30417df4bbaf))
* **deps:** bump aws-java-sdk from 1.12.102 to 1.12.105 ([#404](https://github.com/aws/aws-encryption-sdk-java/issues/404)) ([b87d8c6](https://github.com/aws/aws-encryption-sdk-java/commit/b87d8c6716ba98e1b4e1bb08c841f849aa31ebc2))
* **deps:** bump aws-java-sdk from 1.12.105 to 1.12.106 ([#405](https://github.com/aws/aws-encryption-sdk-java/issues/405)) ([dd633c0](https://github.com/aws/aws-encryption-sdk-java/commit/dd633c037caa0c7ca373cd59f554d49b5cb80448))
* **deps:** bump aws-java-sdk from 1.12.106 to 1.12.127 ([#436](https://github.com/aws/aws-encryption-sdk-java/issues/436)) ([91f6ffc](https://github.com/aws/aws-encryption-sdk-java/commit/91f6ffca2ce0499d08b6ce3259459fbb7cce890d))
* **deps:** bump aws-java-sdk from 1.12.127 to 1.12.128 ([#437](https://github.com/aws/aws-encryption-sdk-java/issues/437)) ([37078ec](https://github.com/aws/aws-encryption-sdk-java/commit/37078ec29805ae23ce7c21e440890d68a9b0956c))
* **deps:** bump aws-java-sdk from 1.12.128 to 1.12.129 ([#447](https://github.com/aws/aws-encryption-sdk-java/issues/447)) ([6872c63](https://github.com/aws/aws-encryption-sdk-java/commit/6872c637b199b3df16104ce3b3b644b90f308c1c))
* **deps:** bump aws-java-sdk from 1.12.129 to 1.12.131 ([#463](https://github.com/aws/aws-encryption-sdk-java/issues/463)) ([a98a321](https://github.com/aws/aws-encryption-sdk-java/commit/a98a321c046ef1af0343ee3c4753c5e1c361bb62))
* **deps:** bump aws-java-sdk from 1.12.131 to 1.12.150 ([#508](https://github.com/aws/aws-encryption-sdk-java/issues/508)) ([433dc1b](https://github.com/aws/aws-encryption-sdk-java/commit/433dc1b809a62f7e3bc011b62a55ec4a5e7e90ae))
* **deps:** bump aws-java-sdk from 1.12.150 to 1.12.151 ([#510](https://github.com/aws/aws-encryption-sdk-java/issues/510)) ([70257a5](https://github.com/aws/aws-encryption-sdk-java/commit/70257a5e0d7244682ce8a72c72ea20101113dd48))
* **deps:** bump aws-java-sdk from 1.12.151 to 1.12.162 ([#541](https://github.com/aws/aws-encryption-sdk-java/issues/541)) ([22abc6c](https://github.com/aws/aws-encryption-sdk-java/commit/22abc6c14714ecd164fbb08936d996fd34610b05))
* **deps:** bump aws-java-sdk from 1.12.54 to 1.12.68 ([#341](https://github.com/aws/aws-encryption-sdk-java/issues/341)) ([291be0a](https://github.com/aws/aws-encryption-sdk-java/commit/291be0a722567697cb2fe5174837c83276d626bd))
* **deps:** bump aws-java-sdk from 1.12.68 to 1.12.73 ([#350](https://github.com/aws/aws-encryption-sdk-java/issues/350)) ([153a0b3](https://github.com/aws/aws-encryption-sdk-java/commit/153a0b3ec3e99c3d878ac9f97176138277a35d8b))
* **deps:** bump aws-java-sdk from 1.12.73 to 1.12.74 ([#351](https://github.com/aws/aws-encryption-sdk-java/issues/351)) ([e5f3962](https://github.com/aws/aws-encryption-sdk-java/commit/e5f3962f74da9b4197e37d98e68e722ee0d10e8f))
* **deps:** bump aws-java-sdk from 1.12.74 to 1.12.75 ([#353](https://github.com/aws/aws-encryption-sdk-java/issues/353)) ([3339c20](https://github.com/aws/aws-encryption-sdk-java/commit/3339c20b05e9cbb65317785cf72c3d46087c82c6))
* **deps:** bump aws-java-sdk from 1.12.75 to 1.12.102 ([#400](https://github.com/aws/aws-encryption-sdk-java/issues/400)) ([98b079c](https://github.com/aws/aws-encryption-sdk-java/commit/98b079cb61417f3ee36035d74772f8913ef09518))
* **deps:** bump bcprov-ext-jdk15on from 1.69 to 1.70 ([#439](https://github.com/aws/aws-encryption-sdk-java/issues/439)) ([969852a](https://github.com/aws/aws-encryption-sdk-java/commit/969852a4bd934f1a50d05b256e6aae82ed8832fe))
* **deps:** bump build-helper-maven-plugin from 3.2.0 to 3.3.0 ([#473](https://github.com/aws/aws-encryption-sdk-java/issues/473)) ([4f7d08c](https://github.com/aws/aws-encryption-sdk-java/commit/4f7d08ca31c09dc6ddbd22bd1d4d4c8629614ea0))
* **deps:** bump fmt-maven-plugin from 2.12 to 2.13 ([#429](https://github.com/aws/aws-encryption-sdk-java/issues/429)) ([e5d8c32](https://github.com/aws/aws-encryption-sdk-java/commit/e5d8c3227ae027105e0195e006dd5a9a2f2fa0d6))
* **deps:** bump maven-compiler-plugin from 3.8.1 to 3.9.0 ([#481](https://github.com/aws/aws-encryption-sdk-java/issues/481)) ([369a049](https://github.com/aws/aws-encryption-sdk-java/commit/369a0498127377ae3b4cdfa3649c612f18a4582a))
* **deps:** bump maven-javadoc-plugin from 3.3.0 to 3.3.1 ([#333](https://github.com/aws/aws-encryption-sdk-java/issues/333)) ([693e43f](https://github.com/aws/aws-encryption-sdk-java/commit/693e43fb9606824e8b4f5336ef8d06cf454338de))
* **deps:** bump nexus-staging-maven-plugin from 1.6.11 to 1.6.12 ([#546](https://github.com/aws/aws-encryption-sdk-java/issues/546)) ([6fa782b](https://github.com/aws/aws-encryption-sdk-java/commit/6fa782bb830273bf09cf80e0f14fc3be774ea276))
* **deps:** bump nexus-staging-maven-plugin from 1.6.8 to 1.6.11 ([#535](https://github.com/aws/aws-encryption-sdk-java/issues/535)) ([0ab1db0](https://github.com/aws/aws-encryption-sdk-java/commit/0ab1db09d10c9477167dd0545747e1391090727b))
* **docs:** update README get started example ([#423](https://github.com/aws/aws-encryption-sdk-java/issues/423)) ([da0fe89](https://github.com/aws/aws-encryption-sdk-java/commit/da0fe89836c40e33f201b792052f02abe44af92b))
* **docs:** updating broken javadoc link ([#366](https://github.com/aws/aws-encryption-sdk-java/issues/366)) ([487be4b](https://github.com/aws/aws-encryption-sdk-java/commit/487be4b8765e92b4b5b8d840133955573e8710da))
* moving and renaming buildspec.yml ([#360](https://github.com/aws/aws-encryption-sdk-java/issues/360)) ([e259caf](https://github.com/aws/aws-encryption-sdk-java/commit/e259caf3c50ab4c3346ca8e203cc6d6878482aa7))
* release updates ([#369](https://github.com/aws/aws-encryption-sdk-java/issues/369)) ([4b9d932](https://github.com/aws/aws-encryption-sdk-java/commit/4b9d932a6d8f5085db34b0f8a693f9cfc0d04b49))
* source controlling cfn templates that will be used for our release process ([#345](https://github.com/aws/aws-encryption-sdk-java/issues/345)) ([456dda0](https://github.com/aws/aws-encryption-sdk-java/commit/456dda0a8d6a2b3ce67024cc0b52edd24ec2816b))
* update dependabot to update mainline-1.x ([#440](https://github.com/aws/aws-encryption-sdk-java/issues/440)) ([960f3e5](https://github.com/aws/aws-encryption-sdk-java/commit/960f3e5459d196b1d623d61d9d780fa519b106ad))
* update gh token ([#412](https://github.com/aws/aws-encryption-sdk-java/issues/412)) ([f8ada9b](https://github.com/aws/aws-encryption-sdk-java/commit/f8ada9bcd3c804abcf1747ffb1cefbdff8c1e576))
* update release process ([#396](https://github.com/aws/aws-encryption-sdk-java/issues/396)) ([c0ff093](https://github.com/aws/aws-encryption-sdk-java/commit/c0ff093c633cabc21d537ff8e27d6a41d08a772c))
* update releaserc to include pom.xml file ([#357](https://github.com/aws/aws-encryption-sdk-java/issues/357)) ([63e2f05](https://github.com/aws/aws-encryption-sdk-java/commit/63e2f054929b056bdd74328b94c5f96577626113))
* update token name and timeout ([#411](https://github.com/aws/aws-encryption-sdk-java/issues/411)) ([c0d5a0e](https://github.com/aws/aws-encryption-sdk-java/commit/c0d5a0e8c8564ece51f4c43c99ae7bfcc4ab71d5))
* updating prod template to remove resources and abstract ones ([#354](https://github.com/aws/aws-encryption-sdk-java/issues/354)) ([ecc17a6](https://github.com/aws/aws-encryption-sdk-java/commit/ecc17a6789a204fdc9bded0fa335b7087f0b371b))
* Upgrade mockito to 4.0.0 ([#438](https://github.com/aws/aws-encryption-sdk-java/issues/438)) ([629dbfd](https://github.com/aws/aws-encryption-sdk-java/commit/629dbfdaa91b6023034f808f5e4865fd7048c963))

### 2.3.3 -- 2021-08-26

### Maintenance

* chore(deps): bump aws-java-sdk from 1.12.26 to 1.12.54
([#299](https://github.com/aws/aws-encryption-sdk-java/pull/299))
([#301](https://github.com/aws/aws-encryption-sdk-java/pull/301))
([#302](https://github.com/aws/aws-encryption-sdk-java/pull/302))
([#301](https://github.com/aws/aws-encryption-sdk-java/pull/301))
([#311](https://github.com/aws/aws-encryption-sdk-java/pull/311))
([#312](https://github.com/aws/aws-encryption-sdk-java/pull/312))
([#315](https://github.com/aws/aws-encryption-sdk-java/pull/315))
([#317](https://github.com/aws/aws-encryption-sdk-java/pull/317))
([#319](https://github.com/aws/aws-encryption-sdk-java/pull/319))
([#321](https://github.com/aws/aws-encryption-sdk-java/pull/321))
* chore: Bump fmt-maven-plugin from 2.11 to 2.12
([#318](https://github.com/aws/aws-encryption-sdk-java/pull/318))
* chore: Bump mockito-core from 3.11.2 to 3.12.3
([#316](https://github.com/aws/aws-encryption-sdk-java/pull/316))
([#320](https://github.com/aws/aws-encryption-sdk-java/pull/320))
* CI: Compilation with OpenJDK11 and validation with other JDKs
([#293](https://github.com/aws/aws-encryption-sdk-java/pull/293))

### 2.3.2 -- 2021-07-20

### Maintenance

* Bump maven-gpg-plugin from 1.6 to 3.0.1
([#259](https://github.com/aws/aws-encryption-sdk-java/pull/259))
* chore(deps): bump aws-java-sdk from 1.11.704 to 1.12.26
([#284](https://github.com/aws/aws-encryption-sdk-java/pull/284))
([#281](https://github.com/aws/aws-encryption-sdk-java/pull/281))
([#280](https://github.com/aws/aws-encryption-sdk-java/pull/280))
([#278](https://github.com/aws/aws-encryption-sdk-java/pull/278))
* Bump maven-javadoc-plugin from 3.0.1 to 3.3.0
([#267](https://github.com/aws/aws-encryption-sdk-java/pull/267))
* chore: Bump maven-compiler-plugin from 3.8.0 to 3.8.1
([#276](https://github.com/aws/aws-encryption-sdk-java/pull/276))
* chore: Bump fmt-maven-plugin from 2.10 to 2.11
([#275](https://github.com/aws/aws-encryption-sdk-java/pull/275))
* chore: Bump junit-vintage-engine from 5.7.1 to 5.7.2
([#268](https://github.com/aws/aws-encryption-sdk-java/pull/268))
* chore: Bump mockito-core from 3.8.0 to 3.11.2
([#270](https://github.com/aws/aws-encryption-sdk-java/pull/270))
* chore: Add support policy
([#274](https://github.com/aws/aws-encryption-sdk-java/pull/274))

### 2.3.1 -- 2021-06-29

* fix: read project properties from package's own ClassLoader [(PR #269)](https://github.com/aws/aws-encryption-sdk-java/pull/269)

### 2.3.0 -- 2021-06-16

* feat: AWS KMS multi-Region Key support
        
  Added new the master key AwsKmsMrkAwareMasterKey
  and the new master key provider AwsKmsMrkAwareMasterKeyProvider
  that support AWS KMS multi-Region Keys.

  See https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
  for more details about AWS KMS multi-Region Keys.
  
  See https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks
  for more details about how the AWS Encryption SDK interoperates
  with AWS KMS multi-Region keys.

### 2.2.0 -- 2021-05-27

* feat: Improvements to the message decryption process. 

  See https://github.com/aws/aws-encryption-sdk-java/security/advisories/GHSA-55xh-53m6-936r


### 2.0.0 -- 2020-09-24

* feat!: Updates to the AWS Encryption SDK. 4678ffa

### BREAKING CHANGES

* AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html

### 1.7.0 -- 2020-09-24

* feat: Updates to the AWS Encryption SDK. a6be12a

### 1.6.2 -- 2020-05-26

### Patches
* Validate final frame length does not exceed the frame size in the message header [PR #166](https://github.com/aws/aws-encryption-sdk-java/pull/166)
* Validate entire ciphertext has been processed before returning [PR #191](https://github.com/aws/aws-encryption-sdk-java/pull/191)

### Maintenance
* Update AWS Java SDK version from 1.11.561 to 1.11.704. [PR #186](https://github.com/aws/aws-encryption-sdk-java/pull/186)
* Upgrade Bouncy Castle from 1.61 to 1.65 [PR #179](https://github.com/aws/aws-encryption-sdk-java/pull/179)

### 1.6.1 -- 2019-10-29

### Deprecation Warnings
* Deprecated `AwsCrypto.encryptString()` and `AwsCrypto.decryptString()`.
  Replace your calls to these methods with calls to AwsCrypto.encryptData() and AwsCrypto.decryptData().
  Unlike the deprecated methods, these methods don't perform any Base64 encoding or decoding, so they are fully compatible with other language implementations of the AWS Encryption SDK.
  
  If you need Base64 encoding or decoding for your application, you can add it outside of the AWS Encryption SDK.
  [PR #120](https://github.com/aws/aws-encryption-sdk-java/pull/120)

### Patches
* Correctly validate version [PR #116](https://github.com/aws/aws-encryption-sdk-java/pull/116)
* `ParsedCiphertext` now handles truncated input properly [PR #119](https://github.com/aws/aws-encryption-sdk-java/pull/119)

### Maintenance
* Add support for standard test vectors via `testVectorZip` system property. [PR #127](https://github.com/aws/aws-encryption-sdk-java/pull/127)
* Remove all explicit cryptographic dependencies on BouncyCastle. The AWS Encryption SDK for Java still uses Bouncy Castle for other tasks. PRs
  [#128](https://github.com/aws/aws-encryption-sdk-java/pull/128),
  [#129](https://github.com/aws/aws-encryption-sdk-java/pull/129),
  [#130](https://github.com/aws/aws-encryption-sdk-java/pull/130),
  [#131](https://github.com/aws/aws-encryption-sdk-java/pull/131),
  and [#132](https://github.com/aws/aws-encryption-sdk-java/pull/132).

### 1.6.0 -- 2019-05-31

### Minor Changes
* Remove dependency on Apache Commons Codec 1.12.
* Use Base64 encoder from Bouncy Castle.
* Introduce and use utility methods for Base64 encoding/decoding so that
  switching the codec provider needs to be done only in one place next time.

### 1.5.0 -- 2019-05-30

### Minor Changes
* Added dependency on Apache Commons Codec 1.12.
* Use org.apache.commons.codec.binary.Base64 instead of java.util.Base64 so
  that the SDK can be used on systems that do not have java.util.Base64 but
  support Java 8 language features.

### Maintenance
* Upgrade AWS Java SDK version from 1.11.169 to 1.11.561.
* Upgrade Mockito from 2.23.4 to 2.28.1.
* Upgrade Apache Commons Lang from 3.4 to 3.9.

### 1.4.1 -- 2019-05-10

### Patches
* Cast ByteBuffer to Buffer prior to using some methods so that it works properly in Java 8.

### 1.4.0 -- 2019-05-10

### Minor Changes
* Increased BouncyCastle dependency version to 1.61
* Removed explicit use of BouncyCastle from all cryptography except for EC key generation and RSA encryption/decryption

### Maintenance
* Increased Mockito test dependency version to 2.23.4

### 1.3.6 -- 2018-12-10

### Patches
* Fixed typos in Exception messages (excryption -> encryption) #78
* Fixed DecryptionMaterialsRequest.Builder to copy EncryptionContext #77

### Maintenance
* JML Specifications for CipherBlockHeaders #74
* Minor Java code cleanup #73
* Added JML specs in #72
* Ensure that KeyBlob treats field lengths as unsigned shorts #71

### 1.3.5

### Minor Changes

* Restored the KMS client cache with a fix for the memory leak.
* When using a master key provider that can only service a subset of regions
(e.g. using the deprecated constructors), and requesting a master key from a
region not servicable by that MKP, the exception will now be thrown on first
use of the MK, rather than at getMasterKey time.

### 1.3.4

### Minor Changes

* Removed the KMS client cache, which could result in a memory leak when
decrypting certain malformed ciphertexts. This may reduce performance slightly
in some scenarios.

### 1.3.3

### Minor Changes
* Move the `aws-encryption-sdk-java` repository from `awslabs` to `aws`.
* Log a warning when an unsupported asymmetric algorithm is used with `JceMasterKey`
* Make `JceMasterKey` case insensitive
* Fix bare aliases not using default region

### 1.3.2

### Minor Changes
* Frame size restriction removed again
* Support Builders for use with AWS KMS
* Fix estimateCipherText when used with cached data keys
* Do not automatically set a default region in KmsMasterKeyProvider

### 1.3.1

### Minor changes

* Frame sizes are once again required to be aligned to 16 bytes
  This restriction was relaxed in 1.3.0, but due to compatibility concerns
  we'll put this restriction back in for the time being.

### 1.3.0

### Major changes

* Synchronized version numbers with the Python release
* Added cryptographic materials managers
* Added data key caching
* Moved to deterministic IV generation

### Minor changes

* Added changelog
* Made elliptic curve signatures length deterministic
* Various minor improvements
