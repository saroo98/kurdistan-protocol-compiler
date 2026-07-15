// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

type generatedProfileParityPinV1 struct {
	seed                                                                                                                                       int64
	tuple                                                                                                                                      policyMatrixTupleV1
	profileHashHex, policyHashHex, framingHashHex, stateHashHex, schedulerHashHex, paddingHashHex, streamHashHex, proxyHashHex, carrierHashHex string
	replayWindow, maxStreams, maxFrame, maxEnvelope                                                                                            uint32
}

// generatedProfileParityPinsV1 is the sole reviewed literal pin ledger. Every
// alternate authorization representation is derived from these typed rows.
var generatedProfileParityPinsV1 = []generatedProfileParityPinV1{
	{1, policyMatrixTupleV1{"canonical_full_binding_v1", "counter_xor_base", "windowed_replay", "suite_bound_transcript", "intersection_with_required", "schema_and_feature", "message_lifetime_bound", "strict_with_redaction", "full_context_bound_envelope", 256, 16384, 16384}, "445fb59a74793cb5f864060ed9c3ddb5e557f4f81c55b1e4e7e730c6735ae9a1", "b387522a5e93aa6a0896ddc25181931dd3b7f6db038b2e36acba5af5c768492a", "0ae66add32f46bc5bd7e5ebf713da2bc6e0235d499a1a614b95b52d07c329e32", "8d06c12ac250e8ebe2bc285c04d50213e8150f4cb4df63833382311a3ef8b9cf", "07153ca5b0e22206e9b45071d304bf611264c2887bea72547452f283cd1734fb", "deccf79ce7692c4a4c1bc26d92202f5f32a2aa280f78fc9c30a1cbf5b8900d71", "51c9145db54640e50ff9ac20748d68594dfa4fc096733d35fb69a6672ccbe466", "98884a0f1123713765929aada96812c9c2ede81df24f2c524a3db2945ecb2b8f", "0dd7b5e3574b5b96a74b2b04ed75bec5e7e855ac64a42f92afbe7f47fbbad9f8", 256, 8, 65536, 4096},
	{2, policyMatrixTupleV1{"canonical_v1", "counter_append_base", "windowed_replay", "suite_bound_transcript", "profile_declared_required", "full_policy_binding", "profile_lifetime_bound", "strict_profile_bound", "full_context_bound_envelope", 256, 131072, 16384}, "0ff32f626dcbb105239861caefaf38598004667e5e6993924bd5306fff1a658f", "42a179825dd4ec762fde37dc840f916435e668c3045664ede06c9b5895996087", "ebb01d096febe88778c3b3e5fc237fa0ddbecff8b7bfaf17629594a437b2a7f3", "f723a4763d9d1c0e066918b888ec6f270d9693378ba29ebe8d15313c3e3a4f87", "1c8137bd52d7db265014821c080d6127336e03ef00704556370db5c8bb9bea80", "3557be6a20ba457aa6b9479d4251cc734a6d160d6fb093d1fbb8e139fef70ffb", "4472ab794385b138666e9c502aea7f30ec15e1ce7f00d55b0b4ab75fc7fcc602", "1cf883c619cf2888eee47844046887a5569631fc966ea1a77d5c1d553e9055da", "84c8ed71927f31132949943b61a80bc5700c8ae36b20746c18a3b945b01782a6", 256, 4, 65536, 8192},
	{3, policyMatrixTupleV1{"canonical_v1", "counter_append_base", "windowed_replay", "strict_capabilities", "strict_required", "full_policy_binding", "message_lifetime_bound", "strict_with_redaction", "full_context_bound_envelope", 128, 131072, 8192}, "84f477c9c18e4898bfa3b82d1a2918bb18b4d8f88754a743cfef37983c2d50cb", "b66bc2ca56d613beca4eb3e2ed70d0f7cf9eba56b7dbc17f09492d3489444dd5", "e5101002212eec89e8fd408500b1b81c02533e99f05064fe3614118ff3fb9435", "66fe8953a74553ee5da8474bc356f06f1aeaee14e3f763e38037a0efe9b6ee40", "705fd122ba5db3d30da598786c2c9b46fc2a544ff2c97ce83e7d73c216d815a1", "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36", "42c7570fa3748c02c50c4f06d877f1ec54cd308de0f7678e0a390c18346f9108", "7c3b5c2cae07f18855deaa592baa9c16f7b3964f38013c57ae4a2e620486ebf2", "631cc5e9350dc5da496086ae71a9e7464e308b6058de977b4c14ce77cda38b37", 128, 8, 65536, 16384},
	{4, policyMatrixTupleV1{"canonical_v1", "directional_counter", "ordered_only", "suite_bound_transcript", "strict_required", "full_policy_binding", "session_only", "strict_profile_bound", "synthetic_aead_test", 128, 131072, 4096}, "6bb5a39a97828f8e097d2a5dcb244a252bf49e325de8c793ea39fe55e94df980", "3d3ef057e66ff5ad987b58fc74a9b52567f3186a9b179119bddbe940bf13c4fa", "a404d7d81b493e9e0ddbafc9dd07c895c9bae818ddb968eeb5a2ccff0c65114f", "88c3af31edfa765f6aebbf8fe175dc3123942717168deb2b57d85c301dafec07", "e15120dff28f5737aab3ee3f4a1364ad169c70bb9e9575cc9f824ab41860c4f3", "c7b513c2ed5bc56ec3c606564f60b8a0499de02a79b157123834ad227a8d1fb5", "4bc9313a861fc783ef303d7c35db343cd58bffa0cfe078ce212bce76bc4ba392", "634aed170481afedd2ca39bdbbaf64fdfb61e2369126195c3d85dc9559e23eb9", "a873072eaaf9d2b34c6d1dd4e996c73dd75f4dca2afe7c33d4fe9cc45fc76634", 128, 8, 65536, 1024},
	{6, policyMatrixTupleV1{"canonical_full_binding_v1", "counter_append_base", "windowed_replay", "strict_capabilities", "strict_required", "strict_schema", "message_lifetime_bound", "strict_with_redaction", "synthetic_aead_test", 32, 65536, 4096}, "f84ba1cf9104dc28ef5d42c4661805a31e146772a88eb454b44fd9184b47b071", "8c73808f506cda6fad07714b0cebcf8b4eb661e3de679d776489f341a0e56bae", "de89d310204a95faf52bc7b2e367ebb75c1861ad8aaea14a5adacdb5a4bd0ab8", "1b263804934f8e9f4e4f0d0ca9d099ef3ec5db1cc442c67910213155b5a7bbae", "a804c36f77da40a078a5431ea751ce88d96c95f58f51755e1b77e39c6c3b36fc", "85d958e5cf2fc9fe3018aaa3f52729aaf183d63b27cbad907288a3fbf96db27e", "2eb2204a62244eead363ec74e055e3b055582d7570b221d38ede10d98fead3fc", "d94c698a6c0149d0de43263a3953a236beab62da4d5423f2d384ae7caff5b2d5", "4811c14fcd09171b26b280646d2f62cd6812e102cc10aa04b274b9b8948abd85", 32, 16, 65536, 1024},
	{7, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "counter_xor_base", "ordered_only", "strict_suite_and_capabilities", "profile_declared_required", "full_policy_binding", "profile_lifetime_bound", "strict_required", "metadata_authenticated", 128, 131072, 16384}, "d61bd97c1d3d4eefe3f93e64c7132750dc96ec566373f4a7906bcce8bbe4d21b", "caaacf48e81a01f6fa195d5c6e49d0a390066a16fa3a6ee48f8672765a6ef8f9", "13892230a03796b7b501bd8c3c61115764627faf34972a5f0eb2472439146a49", "e7e8a0f04b82a4f0457d88d9b0739092f9913a6c41ffc5e92289d10b38c5e757", "578e1b56dfafb0c0464b04fe8e0621a3a37a005ab1bdce35a1cfae111fefe0f5", "e30b6cbfcc447dfed9098a59f79fa442d52db5242da925ff4ec814234435ada8", "a7cf1c53a2660c28c913f5b4d9021c0848fd1389c45eb0798f09bc62a88a98e8", "7d3318e127022dae6d4bdfbaf34586ec8f7ae6f820ea8c8477ced9541266c998", "579e25c59bffbb99b006a9158b0b6691a04731f239fce28ff8103a3cbfdb4723", 128, 4, 65536, 4096},
	{19, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "stream_partitioned_counter", "windowed_replay", "strict_suite_and_capabilities", "profile_declared_required", "schema_and_feature", "message_lifetime_bound", "strict_profile_bound", "metadata_authenticated", 32, 32768, 4096}, "77f825a7c16360a81e706a5114204702e2a529ff99e1a62438141876b377399c", "992d549d4386763215a978014e12bf81315d92ef19d69f544ff0ca127f4d7b9b", "92c6fe1e16e2cb30c6ca2dd68fdc2502be81f516a43b8f9dc04696dad71818b7", "b88350a91f9aacb3af0a4aefdfbf56b27390fa3d3c71c79576ff673c7edee3b0", "4d4d942685bd6ba31bf7d3c61ffa34d2e2fd0053b0b78b065685c07f54b12247", "302e4a250262367f8a1a3d52e2aa04f05c7637b9df92bf061ae1f8b4459d6f84", "e2d7ccc12d49ab30b70d7d71511f07a59a1e92549422f4bf23bde55f7a2d0e2b", "37d601fc49cfa4b024ad97ae995a839c04ee075dd66e033525e072a0632f9a66", "ef25b8e2bd67beae54fdb85170a44ed89394eb8ea85dfaf91214180b8aed083c", 32, 4, 65536, 2048},
	{25, policyMatrixTupleV1{"canonical_v1", "stream_partitioned_counter", "bounded_reorder", "strict_suite_and_capabilities", "strict_required", "strict_schema", "profile_lifetime_bound", "strict_profile_bound", "synthetic_aead_test", 256, 16384, 16384}, "3ce0465f2934e665054ceeef0663d715166be8d2c4fbfe7019f8ee87a066d4cc", "a086901967909b50f0fdfde8792e943bfb05dea26084408d29b49da53f39f566", "b7978fe65c7578a487ee457618187e798dc69b04510e4730a871cee8f0e1c215", "e86b49cba4ae5a058c5527fb22f61dc2d180728d15d6880426d03ea2935c890b", "d4ea9933c1602c2117690ad266ebd338944af56c7eefc08998d9409c424f6c4e", "e0cdb3838c013221b3be53c05ac4d3c959a5ac9ccd9b32dcb0651413d942ad8b", "1ac8d30b2e921a5f0d2803f7f1ba6330795b557b197b2088bc8803aeed3c460a", "e99400e6e0701673acf95290a4d085befcd9a07a0f582bc52fa5c392c8a17ad8", "7ddad99c5cdad3151f6c1460fff58651feec0d964ece07438a2a432db83c367d", 256, 8, 65536, 16384},
	{26, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "counter_xor_base", "windowed_replay", "strict_suite_and_capabilities", "strict_required", "full_policy_binding", "session_only", "strict_with_redaction", "metadata_authenticated", 64, 65536, 8192}, "23c8743c8851f6a677cbfe11653d97677e75ca361cbf0388fb98aded6ca541dd", "21577bc8b4aadaf1cd3a3437ee505e8f0f6479ec932d335bdaaea74ef2d32678", "6c20382c20870e2412b291b3eb53ec5ad09b9432d89826e3b28d44d48ff6110a", "064aec55e6ace22979c628946e38bece9e1f32f7662c59062c610f4ae82d02cf", "39feb01dd109507896027c596992ca424e6219ea2c798ad59e72d8aeead6b363", "ef7d69f7762fbb19377001f4704985c6751fd47f9a66b35ec8d02e5d3c7c763d", "fffe07dabc8614c12da481e786ea96079f07305fde09cf10144eb75d8a8dd295", "0a916a5c64594e2344c49f3c017c497020792435a066e199fac25d2f59efe88b", "ad83ee3e7621c640f6c1c1613fb19261db892e029f1a9564c907aac67e89eff9", 64, 8, 65536, 2048},
	{27, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "counter_append_base", "windowed_replay", "strict_suite_and_capabilities", "intersection_with_required", "schema_and_feature", "message_lifetime_bound", "strict_with_redaction", "synthetic_aead_test", 128, 16384, 8192}, "4624b745792419a837893636bb7e486ec511a32bcc8c03f36676f2e1feeebc29", "06036e835597c66fa5de6a838ed204cb4989a3bb254cb0b995be29dbc44b5696", "de0ae5fe8f9086e21cefc4c503fbd2bce3d4e4fb4c226d19d96f0527c5681c86", "77fbe5bd80e1c830e3f8a6292a1b4860a2eb13dac9ba55a3808006bf7440046f", "cff7b464e64efc621e45c7d6cb34fd8674cb615ede0b33ed6ec1cb1d0b4c20b1", "00b92321f7ec2b228eedbe4cfb872e84b8701152623b0b6d454c7d5ad51cc2f1", "fdeab4a5dbddf65f9d54fb9d8d7792fb3fe213f3788c6929788b44dff405f391", "e144da4af9974e94ca6b6a7c58d75119f0e038162face40720788e3e6bbd34a6", "a384729940f31a289fe41b8cef1478710b1ef8c4ba1403e1e1986b0dcf5d0c7a", 128, 4, 65536, 1024},
	{35, policyMatrixTupleV1{"canonical_with_capabilities_v1", "directional_counter", "bounded_reorder", "strict_suite_and_capabilities", "profile_declared_required", "full_policy_binding", "message_lifetime_bound", "strict_profile_bound", "synthetic_aead_test", 64, 32768, 8192}, "27cc6bb23ef3e15456620923da39577809e360c08770757708610a8e4d164cd9", "7d911682d20f6f392adfdc176ba5b1cdd5abc879cde50dbbaa93ea694d07bea1", "2bb58c25e34038502260cc46b4412600fab244293f468480d5bf2af0c8a6ce94", "425f836cebcefdf672209bab87d9e1afed4f2e993a65f4761665c2e5c70b3622", "d56705887cb274c5be1fc8b8d174f70a251102baa9924d2e667e9b5a47d56412", "2afdad19f642c100591faf0f5d668f26b121de68aa87a7c9f433d3488a4e7acc", "f1bc650b0e13afe4d8e97b2bf69423eacbcf4075b40408fffa0cb5fec6140687", "e3ff314331d46d2e67169f3db12fd1f83c3498c656786697c3c2483acdf37ade", "b31f747d298fb6d339a508d577ec16530b552dab5f05c310633ec823fe260657", 64, 2, 65536, 1024},
	{40, policyMatrixTupleV1{"canonical_v1", "stream_partitioned_counter", "windowed_replay", "strict_capabilities", "profile_declared_required", "full_policy_binding", "profile_lifetime_bound", "strict_profile_bound", "full_context_bound_envelope", 32, 65536, 16384}, "ca64e6ed193a72805f4607dd97a5f57d09244f2fcb96d50115f350df091e0805", "feb81ee04acae79766fbfd1f6a621b5298dcdf198aa0bbc19375d1c9a86e138f", "39f1acf1306fab95652e847da617bb8ba1e4f76460201f56670654516575ea0d", "23a237fce155d21c8c62b2ca24f16a0e5d16a838be0108fce49e0de6cc0cdbcd", "3929871d5f48b00b78d6712d4be56e03ad6981e422389d2ec2e6c7ba5a5cb386", "62551e6498549853f43b3ecfdc84172e3e3555ee657c3617a29ca3061a86b4f1", "7eb926433e0e9cff9ccba0cffc2924fc3a653ea4f3cdc96347a6b663852c102f", "55e92c3cb818184d5b192360d4969fea114ad59482f0abf9ddadf95154e1dbe9", "682cf39fab9e021e2b016530edb835af23d4c0bc34b7f424a90222b0b74cd99a", 32, 2, 65536, 16384},
	{42, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "directional_counter", "bounded_reorder", "strict_suite_and_capabilities", "intersection_with_required", "schema_and_feature", "session_only", "strict_with_redaction", "synthetic_aead_test", 128, 131072, 16384}, "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", "9a208cab2e4393c3c6417fc1436a1a7c9959dce4a50ac435baaf5d8b72d5bad7", "1e01c3b207af2122b5dff65f1945f7dbad96c288163e5deb65684e9ed297da6c", "ccf2a4742252f71b3d4aaa5cc9c0e26f00222df81dd7c9020afb1ca6ae48489f", "8c27f74766a072e98e7a3108c02dd1680f6381178e23323fc8422b3f5f574930", "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36", "2bf26abe3667e47418a4fc935f8aeb18f64620454dd1ee234faba4ddcd9e2c90", "3e4bbe2759342669767541930cda069f9bee0b3b419c3016b64ee05621124ebd", "f71bd073932bf7de9a4df9dd0f666827849f9a87f895de98c5813f7474a116b2", 128, 8, 65536, 8192},
	{58, policyMatrixTupleV1{"canonical_with_capabilities_v1", "counter_append_base", "windowed_replay", "strict_capabilities", "profile_declared_required", "strict_schema", "session_only", "strict_with_redaction", "metadata_authenticated", 256, 65536, 4096}, "aa24580ba515c64ee2ccea48b0c6b8e8a69ee1f7713df2f9811e306ea7701931", "970bcd6af98f4bc9356da366c2541956f6f6ea1304b82df8504583216df0088c", "73a4656b32ea071b9ed53fbca80ad05181def0baa6f06329ac089481746595d1", "1cc3817102ce4830b1365c3b597710799166b60547049f578677788bafa77664", "9642240b3a1b3d6f3ed6d874b08f4f4f83c6307313a1946c1256abd62c40b6ea", "5d24faf740597e376b856be2cf77ef3a9604f5f45b4a23994895b3dced859791", "c19b168b39ec60014693d1300717474b85cc50905211919676acda1926bf977c", "02896bfe0ac2e22981cb17774b821715a3f8d1289b9e86d383a799df6c2468dd", "b13ec2a91f0b08f716f21a40a66620948e063c738b501aceb9c762b7e309e589", 256, 2, 65536, 16384},
	{66, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "counter_xor_base", "bounded_reorder", "strict_suite_and_capabilities", "profile_declared_required", "strict_schema", "profile_lifetime_bound", "strict_with_redaction", "metadata_authenticated", 32, 131072, 16384}, "1e72424116e008895c5d5cef4fea53c537fb7aa44bb24579da0761583b6a7b0a", "b57e7dc6639d8eeb9aec8332fa8f42e72781e949f407ca267727676b35bff538", "724febf1c93c35e1848b91212d2eaa1a61daa4bce64244eb54c2d8ab088e38ee", "d45a1e23947b9cbbb79951b8be284259ca2ecf3cba5e861a3bf6d4e707bb2e44", "c98a7287ef077dbfd735b17c6b00f76d9dcd8b9d2a2b591354a6f74ea8fa7415", "6ca069328f38b45713f4ccd7686a8f55ed2b8193958cdd7954b3b89b1c876092", "dd085bdb0c30c063d5a5f192734b885e8246fed612333669d5b949ffafb2f30d", "c41461e655b9dc5225a7ba047a0c555e33e38c38fbf4fc503a11ee45bea89384", "4fe83d17c90c662f8947ba71dab30e53ae2994df8e029b702b6007ac90e7338f", 32, 4, 65536, 4096},
	{69, policyMatrixTupleV1{"canonical_full_binding_v1", "directional_counter", "ordered_only", "strict_capabilities", "strict_required", "full_policy_binding", "profile_lifetime_bound", "strict_required", "full_context_bound_envelope", 256, 32768, 8192}, "88e2b78c353d4e0092a09635a26c82b58dd4c66b98eb81e8fa7981a7ae87e7be", "3017dcad8d84cd07febac98684a744810c46ae4a3c6c28b874071903585a7889", "ce137ad27fac5fc08e530af7f412e4ef61461411e285cb76213f5b94dc7bd0a4", "d1b403d9735e415d7be715be13ecba20dee3ce87ea859b890c14624e920ecac5", "b737433f57655ce3a73d0f5114096c3ca990e4425dc1ffdeeda8df46db15802b", "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36", "ed051a99c97e9566f8161990070bac9d4547f8c709c103b4a9d23068c14f7b0a", "faec204eecf02e9e5c8a50babfebd46c91b65f99b402783bb2b8dc592c6367c2", "fade7f9d8c89589ce1c33d228408d3353649cef3731ac43efe65947a922ad595", 256, 4, 65536, 8192},
	{78, policyMatrixTupleV1{"canonical_full_binding_v1", "counter_xor_base", "windowed_replay", "strict_suite_and_capabilities", "intersection_with_required", "full_policy_binding", "session_only", "strict_profile_bound", "full_context_bound_envelope", 128, 32768, 8192}, "a6664dff55499b3d5b28aa267a6a23a425c6ef00c779fe70475dde572921bff4", "e564961e2d33d169e03e9ca74df2ead7101d1e767e6ab4f9ce5b69b04810ddaa", "32a33696b6d2430fa2510ecc8864921d8eb622388b3f0a7f46db9b4fbdff2d82", "a594b3fe62cff34273d37b0e1f29a2c6723384c5a59afdf442b1089464c95035", "2ce710f920159bdb3e1890eefe1c1553724e92911ae2705dabc46e5d86cfbb9e", "025d2d48ca79b61fc0ebd42e15189a16e339a73651251755370f09d33b6a88b1", "f3945408c64f6992227e099d9811b92a943c5b470a99da804d210f692e56f102", "2ba2028497d0c87e4299972f239af49ef127f355ed1e9acb67649c66ed708e1c", "21945360425d33a1f8883254172c891f6abf3c68cd9eac5d705232d860cd6bbd", 128, 4, 65536, 16384},
	{80, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "counter_append_base", "ordered_only", "suite_bound_transcript", "strict_required", "full_policy_binding", "session_only", "strict_profile_bound", "full_context_bound_envelope", 64, 16384, 16384}, "70da550b100b9aa4cb541b04e86726c7420d660f123973e05f221bd2efcc725c", "cca2f444bf8c304905d51910b5b5904e624c97e2d2e973f579f9af1b04ffd093", "f59d087f8494aa8fa5f6531d8f450423dfc834e16ca5b0adcb2afe1724575397", "e3c52e9f2dad110cb922c20581631ea85703bd38f8f0d138e298fddab1b1abf4", "97816c279dd1c052bab6fdc6882f30e5d49db054d817847412acdaf59e5e53b4", "f179f1a35eafc5dea1b1f635509050fe89d1eb5827dc80682f3a45acf17937d9", "1c73b19ccf151139e7c9680ef02c39e03e18cdbb2169ff8ce34d0a6fdf9d09f8", "82a9c7ca1214b0e2aa5eb168d037c621a23415f28cdbcb821205567f0aed24c4", "f3446cbb3032b2160de2f1746a6e2b09f09f074eca1d00059652cdefd0bf228d", 64, 2, 65536, 1024},
	{91, policyMatrixTupleV1{"canonical_with_capabilities_v1", "counter_xor_base", "ordered_only", "strict_capabilities", "profile_declared_required", "full_policy_binding", "message_lifetime_bound", "strict_profile_bound", "metadata_authenticated", 128, 16384, 4096}, "42ac2f065d0fdf07576c7614dedca25c22f2439780c73a9f74d4d250c682f1b1", "d957cb87a929cc2de9a6dd09a4d4b0dc228cacc7cd9112644f9325027d6fb193", "38687d15cc772badcc72532ec5b5b5b322decd518c54b088991dbdf83b8ad6b6", "4adca86099f6b2ef6a8fd2e1c08fa15f4d789798262322c72b90bd0d0a910771", "7d818e760e36b310309f3e29d424f8da29b0a2c5d0acc6914f425b33ca829226", "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36", "ef25b29f7830352fb8f1f4031068769a5963900d0b32a75fe59b66e11bed982a", "4da0518e3ece20d6d24f25e0cecbf34f713cc25c5c8d0113105f2ea2b027b43f", "42df9dea611a369f05d13c4cd6d1d2783a8539506766b2b12179e30c65221846", 128, 2, 65536, 8192},
	{94, policyMatrixTupleV1{"canonical_with_capabilities_v1", "stream_partitioned_counter", "ordered_only", "strict_suite_and_capabilities", "intersection_with_required", "strict_schema", "session_only", "strict_with_redaction", "full_context_bound_envelope", 32, 131072, 16384}, "f2b520aed64d60a55d316caaf32f74b17ffbc8db9183bc67c05e5eb752ff2ce3", "2fb0960065f4f4e3ad1c01cf2d8e6281ee7dd54b25506015e697fa6819a2d652", "864a3f2a17fdb82be5b4598d35017360f7e76f85c5879852fcda9db6b986be57", "11484a79ffef2df4377bcbdedf2b07d01f4bcaf9aab28cf80a76e8fb550734de", "a4781d6cb908da1ac3bf055df9592bb935d7a108a4de626226bc2576a637139c", "e39ae8b6d0242d2acda1801a0a1a8cca2adeb096194ed9a64bd1ddaf1a25b1d5", "5eeaf1abe1a97facf0c0853ba77cd615a2cc09e7cec8b262fdda566bc261b7c4", "5a826f7f9d0daae1283573c0c935c479d2a8ef5b2742e875371ccdcdc63f50b2", "76b66eaa6a4c5a7379391cecdc9a00d88287680b2e61bb6710a3d530b14bc80a", 32, 2, 65536, 2048},
	{102, policyMatrixTupleV1{"canonical_with_capabilities_v1", "counter_append_base", "bounded_reorder", "strict_suite_and_capabilities", "profile_declared_required", "strict_schema", "profile_lifetime_bound", "strict_required", "synthetic_aead_test", 64, 16384, 8192}, "cd69003e524e04a7ff603e1c742e0307560ca244ef63f8408171cb5f21ee80a5", "5e804a7397510d4dda90e214b8d3723c6f6724b399bb938cf2e0a92d0bb32638", "91966bdf09d544e260e9fab7aadbd778080b4e9add4ddd16e8b463fe45927fd1", "a8859540648de1ba26a1b6a7aa8df1f2e5d7686e6dcf1c60c0d48060d9176634", "edc79d2691fc4111e6470505c675ae9f2079ba6d5445d2a3156d25ac97b7f01b", "56393abdc5c659988bd506cf99f54909ffc0f08da2171cbc12c93f2d3521e062", "077e2ab871edb358c97cc829f484f74f817ffc16c32959edfef4f7f94d38bbdb", "e5a8bb56eb8034e0dca99b83c65c7a6e2b2c69fec2aa55b3f667e6153561d11c", "c08e99a22866b8c6bd9afbb16660fe9db0d006c09f5ad05d413aca936c58ee1f", 64, 8, 65536, 2048},
	{107, policyMatrixTupleV1{"canonical_v1", "directional_counter", "windowed_replay", "strict_suite_and_capabilities", "profile_declared_required", "strict_schema", "session_only", "strict_required", "metadata_authenticated", 32, 16384, 4096}, "cb176a7beb13c9a4349346b4b21ff91fd0942efe69bafe8c4c333398803bebec", "e245d44e1c190f85f06ee5f895d6464ac821be702e9e36aaaeb601f10a823362", "0fdffc021d75a4bb9491943af33509144bd0b542453cace1e944bedb2f1b93ac", "dbe5116aa85c87fe5e6855b9a70f2ef1f00573c32ff156f9a504c7c54851833b", "71b366589fb37c588f3c011f61f6f4a56096dd681b77cea8a112385a1a77200a", "bfb59fe0b7b02582b5673405bd419d4899f7b590586737a65635975e9794b346", "406a043814e731f2ee93b63e80b6e994d767d06e272b1b526e9cef5b23457b1c", "37bd40ba6370fe01e61259596f809f93e0db093a7d3ddfabfee58e2c54770d95", "6f8a39b9f9a933f4211bc17144957b476872218ebc8ba28ffa2129f52c986c4f", 32, 8, 65536, 16384},
	{110, policyMatrixTupleV1{"canonical_with_capabilities_v1", "directional_counter", "ordered_only", "suite_bound_transcript", "strict_required", "schema_and_feature", "message_lifetime_bound", "strict_with_redaction", "full_context_bound_envelope", 32, 131072, 8192}, "344b7de79ac839aa390727e3ffb18d88774ef88d369dc24777f398798e4bb7cb", "0af90e50f35136187dffe161fb3d3e79c27618048b7748bf38f1fc12f0fb9290", "bfd78e6040692163e5402dcc41eb0f26378df5dc00f33687802ab28cc4e12bb1", "d0e214cacab30967d5c7fb72f6ef248dead0d3228dd05599282c593131b952e2", "1400e228c4c654bb0d8b859b906659dbcf36dd799ad10b289a9f79d1aeeec159", "d2f81cf8730f870fdd7dbe5d99ec20148974184aa14e25fc9c93bff567f32a8e", "424d7412e731cddbad04c799c77d4903f7219b1b5380b0ca13fb7db27d2ec19f", "15044a8f7a992e0ed0cf90854be5416a0e6276db21559bebfe33d885843646ac", "8d749259d4dc65426edd6767bdca177db1a78c61ff821b1efa06fe6de3267764", 32, 4, 65536, 2048},
	{123, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "stream_partitioned_counter", "windowed_replay", "suite_bound_transcript", "intersection_with_required", "strict_schema", "session_only", "strict_profile_bound", "synthetic_aead_test", 128, 65536, 8192}, "435f786ddf98abce3cac6757dcbdfa8b080d0e8bf1858eeb57863fe2d0e633ae", "b57cf99fec196461774689ff37f763d4475fc584ce5800e1acfaf83d5e91eaeb", "1ee79f0ba200f4145b3462e14be458b9e139665fe1b2b3edc57115a65784393e", "55da7f991bd23ebf60bbb8ccf665bf1920b020ee8d7c40030052448829501675", "571a32118926067ce804d93df03786b69205208f14c8f16f52a87a164623c57b", "15071097edf3c3dd3c5d80c9b4b72a06efcc195c79d8d5f08e11dfee08ccf361", "842a6e7690c395927a1f903e5f987f8d622821332aeb2495ff9e51878f3663fa", "f129f7d7dc3eeb9dbb92aa3322b1d98248362e629be2c18620ea14b41305eda8", "21a5c974e6298aed8bdc00892b7f190ef431c17874cacf2f9f4792932b5b81f3", 128, 8, 65536, 4096},
	{135, policyMatrixTupleV1{"canonical_with_carrier_binding_v1", "counter_xor_base", "ordered_only", "strict_capabilities", "strict_required", "schema_and_feature", "profile_lifetime_bound", "strict_with_redaction", "metadata_authenticated", 256, 65536, 16384}, "f9049a45c93d021044d364c5c34bd0757525f93958e39c76037fc0a41ef72021", "5f4a36d4e38558890c60f98810b04c00c1c6c721b6a3ee0852a688ba752a229d", "f1536fc0ae37cabe6fa925d755010dc9d474243353f4d717340e776db4aeb73b", "e3377e9059c7d0bbcf0505631a7f63f5c6b782fa04ee485c26c77408ade65317", "a14f6debddf0ddff9670c2ad7cf0b44d4a83f19bb7b45390550ce91ee7e90590", "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36", "289fd7052b8b5f1bfaded67e4c196909004835b5c8de37530174bf9b85842b97", "e90c87c5980dcde8df3f243448c44a0f1970a95b5b2e7875a898d334b94f4f15", "e153d06f59b8caf51ffd78112af39c399c656a62588e09fcfdfe750c3c3e4fa5", 256, 4, 65536, 4096},
	{171, policyMatrixTupleV1{"canonical_full_binding_v1", "stream_partitioned_counter", "windowed_replay", "suite_bound_transcript", "profile_declared_required", "schema_and_feature", "profile_lifetime_bound", "strict_required", "metadata_authenticated", 64, 131072, 4096}, "8dee9d7c306d34505869ea2cb52d51de5e5fde2d0d352b5e0bea30a968ee46da", "625599daa07433c32322ce00bfc3e57b084dbd029f37605bb46bf3696d66de20", "6406c86d3909dcd9425a93105d344407be611a98c9b3b1674b5200d012ebe783", "a9c81eb238cab071dc30ba65211c1bf289fd245e3958801ebeb8b0a6e140d70f", "7db9bb27660274a68d5e40bbacd70ae159443f17b3fd3aac6c805f6b06772de7", "32fa8593e25ff8aac6081b9ea8bf43d8b41abc4f6236309b02f0c8fc6b82d8f0", "38f0560a7e6b130e1860c3c554537a6c0903369a61a9680331d8a9db3c8f0cf5", "2d9143e7707b26cdc28321d8f9249a305a1b94158df1a2c2069e97e1a35dbf64", "4337760b21ddfc68cec502959fcfa94a70dfd0d0aefe87f1d4255f08d0c93e75", 64, 16, 65536, 16384},
	{174, policyMatrixTupleV1{"canonical_v1", "counter_xor_base", "bounded_reorder", "strict_capabilities", "intersection_with_required", "schema_and_feature", "message_lifetime_bound", "strict_required", "synthetic_aead_test", 64, 32768, 16384}, "6dfc4051faccd8d76c848c2773058a2a6145b1400f2c9e22fdd6ce3c0c43840f", "2e8a3a716a2c71e9347d87ce818c2f5f6e7f7e664bea9841e54b2554b08c8a9d", "4de26a1c6830d4908f5f770f8bb8b5c7492a1a62aceeac87141232cd6c75c70d", "ddb01b510ccfe824d35f0c956d896a52d2aed08fe2dce519de0d0015bda16d93", "3bed8240672565d36a32670720a822d795edc6ee987fc0dea13cbb6cd510f958", "ae49361903b62ba73377843b2ccb5e846309aa073487b667e9efe7b549454438", "75db802d05c6c3b629e90fdb4bdf3938cd70d852aeed2e9dff502498bf5bb96d", "8c22797fefc9c0eda42e67dcf77bd8e8cb2254b1c4f956b8de510df6c18036d5", "8f314fccadc5a4ab8288d90fe0b836676f759325b7b8fc3e9bd8d692a0fe787b", 64, 4, 65536, 16384},
	{202, policyMatrixTupleV1{"canonical_full_binding_v1", "counter_append_base", "bounded_reorder", "suite_bound_transcript", "strict_required", "strict_schema", "message_lifetime_bound", "strict_with_redaction", "full_context_bound_envelope", 256, 32768, 4096}, "98a50520125f5b16e2c6b1cc535285fe267f6d2c849d48ec935c13b9d9b2c1a0", "c9f7897729a1066f53994c437353af1fec888529428294385c693546bcc40b05", "c3180f9f7c236dfc4dd9d59faed23ab875abefb4c027f6072cfe293f4d9976ec", "10753f40c0d780a7c3bea94cf4f2b8bdc4720b232bfb783029f5a3318878ffe7", "e350ed3424d6ef5a54798ea498a8adcc49e448fd2ff5075a7c49e86313420eef", "fec95118543519a1ff9a7e41d45ea05368a2d49053a97bc810a23720087b26b0", "3ebe9c3f105185183c01a3de5be850b18f727b7b58f1ecdb0fe64a4fdc2a0800", "0ca2f99e4967e67bd8019f68a5147c0b5c0d265f717b4311cc9835a362ce2519", "6f30f895c84b9ffc5fa3e7bec5d662b46e81b0bce21f5480f7d7ca0cadccd725", 256, 16, 65536, 8192},
	{223, policyMatrixTupleV1{"canonical_full_binding_v1", "directional_counter", "bounded_reorder", "strict_capabilities", "intersection_with_required", "full_policy_binding", "profile_lifetime_bound", "strict_required", "metadata_authenticated", 32, 65536, 4096}, "62b0504f07ead0bf8b9594d74d9c4e1328cd4fe52cf030cc99f0e8112f5f3154", "ba5b5412a8f12371b036e6b52de01365a907b05ac82fa21660a881ac71952b31", "a606ecd55bf957fc57ed86d374bb71741e8c345fc8ea312d0dcb75ef900a2f9c", "34de7dbfd0aae48013c461da95684b349293ac058ca2bada360aee2960aaa887", "616f152554c7e85ddd8504f63482dd619b52115317afe8ff3c3d53a60a0deb4d", "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36", "32d5573c1ba2755ef6961fe47546f182f13a6a01f3328708f0eb503a3764f954", "d7b7b534d8a17ce95e620296241ed9c40eea6db006bf18c025ac2aa9a7a5d760", "3d98c3fde50b371f6f45d4226a72e41dba957967da33c10ad6c53d98fd7f7f96", 32, 16, 65536, 16384},
}

type generatedProfileAuthorizationPinV1 struct {
	seed                                                                                                            int64
	profileHash, policyHash, framingHash, stateHash, schedulerHash, paddingHash, streamHash, proxyHash, carrierHash [32]byte
	replayWindow, maxStreams, maxFrame, maxEnvelope                                                                 uint32
}

func parseGeneratedProfileAuthorizationPinsV1(t *testing.T) []generatedProfileAuthorizationPinV1 {
	t.Helper()
	if len(generatedProfileParityPinsV1) != 29 {
		t.Fatalf("sole pin ledger rows=%d want 29", len(generatedProfileParityPinsV1))
	}
	decode := func(seed int64, field, value string) (out [32]byte) {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != len(out) {
			t.Fatalf("seed %d %s invalid hash", seed, field)
		}
		copy(out[:], raw)
		return out
	}
	out := make([]generatedProfileAuthorizationPinV1, 0, len(generatedProfileParityPinsV1))
	for index, row := range generatedProfileParityPinsV1 {
		if index > 0 && generatedProfileParityPinsV1[index-1].seed >= row.seed {
			t.Fatalf("sole pin ledger not sorted and unique at seed %d", row.seed)
		}
		out = append(out, generatedProfileAuthorizationPinV1{
			seed: row.seed, profileHash: decode(row.seed, "profile", row.profileHashHex), policyHash: decode(row.seed, "policy", row.policyHashHex),
			framingHash: decode(row.seed, "framing", row.framingHashHex), stateHash: decode(row.seed, "state", row.stateHashHex),
			schedulerHash: decode(row.seed, "scheduler", row.schedulerHashHex), paddingHash: decode(row.seed, "padding", row.paddingHashHex),
			streamHash: decode(row.seed, "stream", row.streamHashHex), proxyHash: decode(row.seed, "proxy", row.proxyHashHex),
			carrierHash: decode(row.seed, "carrier", row.carrierHashHex), replayWindow: row.replayWindow,
			maxStreams: row.maxStreams, maxFrame: row.maxFrame, maxEnvelope: row.maxEnvelope,
		})
	}
	return out
}

func TestGeneratedProfileSoleLiteralLedgerV1(t *testing.T) {
	if len(generatedProfileParityPinsV1) != 29 || len(parseGeneratedProfileAuthorizationPinsV1(t)) != 29 {
		t.Fatal("sole reviewed pin ledger cardinality drifted")
	}
	raw, err := os.ReadFile("generated_profile_parity_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	ledgerNeedle := "var generatedProfileParityPinsV1 = " + "[]generatedProfileParityPinV1{"
	legacyNeedle := "generatedProfileAuthorizationPinsV1" + " = `"
	ledgerStart := strings.Index(text, ledgerNeedle)
	ledgerEnd := strings.Index(text, "type generatedProfileAuthorizationPinV1 struct")
	if strings.Count(text, ledgerNeedle) != 1 ||
		ledgerStart < 0 || ledgerEnd <= ledgerStart ||
		strings.Contains(text, legacyNeedle) ||
		strings.Count(text[ledgerStart:ledgerEnd], "policyMatrixTupleV1{") != 29 {
		t.Fatal("more than one literal 29-row pin ledger detected")
	}
}

func TestVersionCutoverAuthorityAndPinsV1(t *testing.T) {
	if ir.SupportedVersion != ir.NextSchemaVersionV1 || ir.SupportedSecurityVersion != ir.NextSecurityVersionV1 ||
		ir.SupportedVersion == ir.LegacySchemaVersionV1 || ir.SupportedSecurityVersion == ir.LegacySecurityVersionV1 {
		t.Fatal("active version tuple did not cut over atomically")
	}
	if security.HandshakeVersionV1 != "kurdistan-handshake-v1" || security.PolicyEncodingVersionV1 != "policy-v1" || security.RecordVersionV1 != "record-v1" {
		t.Fatal("component identifier changed during profile tuple cutover")
	}
	for _, pin := range parseGeneratedProfileAuthorizationPinsV1(t) {
		profile, err := compiler.Generate(pin.seed)
		if err != nil {
			t.Fatal(err)
		}
		policyHash, err := security.EffectivePolicyHashV1(effectiveForProfileV1(t, profile))
		if err != nil {
			t.Fatal(err)
		}
		profileHash, err := hex.DecodeString(profile.GenerationHash)
		if err != nil || len(profileHash) != len(pin.profileHash) || string(profileHash) != string(pin.profileHash[:]) || policyHash != pin.policyHash {
			t.Fatalf("seed %d reviewed cutover pin mismatch", pin.seed)
		}
	}
}

func interpretedProfileV1(t *testing.T, generated *ir.Profile, tuple policyMatrixTupleV1) *ir.Profile {
	t.Helper()
	interpreted := *generated
	interpreted.Security = generated.Security
	interpreted.Security.TranscriptMode, interpreted.Security.NonceMode = tuple.Transcript, tuple.Nonce
	interpreted.Security.ReplayPolicy, interpreted.Security.ReplayWindowSize = tuple.Replay, tuple.ReplayWindow
	interpreted.Security.DowngradePolicy, interpreted.Security.CapabilityNegotiationPolicy = tuple.Downgrade, tuple.Capability
	interpreted.Security.ProfileCompatibilityPolicy, interpreted.Security.KeyRotationPolicy = tuple.Compatibility, tuple.Rotation
	interpreted.Security.ConfigValidationPolicy, interpreted.Security.SecureEnvelopeMode = tuple.Config, tuple.Envelope
	interpreted.Security.MaxSessionMessages, interpreted.Security.MaxKeyLifetimeMessages = tuple.MaxSession, tuple.MaxKey
	interpreted.GenerationHash = ""
	var err error
	interpreted.GenerationHash, err = ir.CanonicalHash(&interpreted)
	if err != nil {
		t.Fatal(err)
	}
	return &interpreted
}

func effectiveForProfileV1(t *testing.T, p *ir.Profile) ir.EffectiveSecurityPolicy {
	t.Helper()
	floor := append([]string(nil), p.Compatibility.RequiredCapabilities...)
	if len(floor) == 0 {
		floor = []string{ir.SecurityCapabilities()[0]}
	}
	effective, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	return effective
}

func parityFixtureFromPinV1(t *testing.T, profile *ir.Profile, policy ir.EffectiveSecurityPolicy, pin generatedProfileAuthorizationPinV1) strictSupportFixtureV1 {
	t.Helper()
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), profile.Compatibility.RequiredCapabilities...)
	client, err := auth.NewPeerParameters("runtime-client", profile, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", profile, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), policy.SelectedCapabilities...), ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2][32]byte{"framing": {view.ClientModeBinding.FramingPolicyHash, pin.framingHash}, "state": {view.ClientModeBinding.StateMachinePolicyHash, pin.stateHash}, "scheduler": {view.ClientModeBinding.SchedulerPolicyHash, pin.schedulerHash}, "padding": {view.ClientModeBinding.PaddingPolicyHash, pin.paddingHash}, "stream": {view.ClientModeBinding.StreamPolicyHash, pin.streamHash}, "proxy": {view.ClientModeBinding.ProxyPolicyHash, pin.proxyHash}, "carrier": {view.ClientModeBinding.CarrierContextHash, pin.carrierHash}} {
		if pair[0] != pair[1] {
			t.Fatalf("seed %d %s component pin mismatch", pin.seed, name)
		}
	}
	pinnedPolicy := policy
	pinnedPolicy.ReplayWindowSize = int(pin.replayWindow)
	pinnedBinding := security.HandshakeModeBinding{MaxFrameBytes: pin.maxFrame, EnvelopeLimit: pin.maxEnvelope, FramingPolicyHash: pin.framingHash, StateMachinePolicyHash: pin.stateHash, SchedulerPolicyHash: pin.schedulerHash, PaddingPolicyHash: pin.paddingHash, StreamPolicyHash: pin.streamHash, ProxyPolicyHash: pin.proxyHash, CarrierContextHash: pin.carrierHash}
	pinnedBinding.LimitBlock.SessionMaxConcurrentStreams = pin.maxStreams
	clientEntry := clientAuthorizationEntryV1(pin.profileHash, pin.policyHash, pinnedPolicy, pinnedBinding)
	relayEntry := relayAuthorizationEntryV1(pin.profileHash, pin.policyHash, pinnedPolicy, pinnedBinding)
	ownerFixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	clientRegistry := ownerFixture.clientRegistry.clone()
	relayRegistry := ownerFixture.relayRegistry.clone()
	pinnedRegistryEntry := clientRegistry.entries[0]
	pinnedRegistryEntry.profileHash = pin.profileHash
	pinnedRegistryEntry.effectivePolicyHash = pin.policyHash
	pinnedRegistryEntry.replayWindowSize = pin.replayWindow
	pinnedRegistryEntry.maxConcurrentStreams = pin.maxStreams
	pinnedRegistryEntry.maxFrameBytes = pin.maxFrame
	pinnedRegistryEntry.maxEnvelopeBytes = pin.maxEnvelope
	pinnedRegistryEntry.framingPolicyHash = pin.framingHash
	pinnedRegistryEntry.stateMachinePolicyHash = pin.stateHash
	pinnedRegistryEntry.schedulerPolicyHash = pin.schedulerHash
	pinnedRegistryEntry.paddingPolicyHash = pin.paddingHash
	pinnedRegistryEntry.streamPolicyHash = pin.streamHash
	pinnedRegistryEntry.proxyPolicyHash = pin.proxyHash
	pinnedRegistryEntry.carrierContextPolicyHash = pin.carrierHash
	clientRegistry.entries[0] = pinnedRegistryEntry
	relayRegistry.entries[0] = pinnedRegistryEntry
	return strictSupportFixtureV1{input: input, snapshot: snapshot, view: view, dependencies: dependencies, clientEntry: clientEntry, relayEntry: relayEntry, clientRegistry: clientRegistry, relayRegistry: relayRegistry}
}

func executePinnedParityChannelV1(t *testing.T, seed int64, fixture strictSupportFixtureV1) policyMatrixTupleV1 {
	t.Helper()
	probe := parityRuntimeV1(t, fixture)
	result, context, err := probe.strictFirstContactWithContextV1(fixture.input)
	if err != nil {
		t.Fatalf("seed %d first contact: %v", seed, err)
	}
	wipeRuntimeBytesV1(result.ChannelSecret)
	clientValue, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatalf("seed %d client config: %v", seed, err)
	}
	relayValue, err := strictConfigFromContextV1(context, false)
	if err != nil {
		t.Fatalf("seed %d relay config: %v", seed, err)
	}
	clientConfig, err := NewClientStrictSessionConfigV1(clientValue)
	if err != nil {
		t.Fatalf("seed %d client config role: %v", seed, err)
	}
	relayConfig, err := NewRelayStrictSessionConfigV1(relayValue)
	if err != nil {
		t.Fatalf("seed %d relay config role: %v", seed, err)
	}
	clientQueue := uint32(1)
	relayQueue := uint32(1)
	if context.EffectivePolicy.ConfigValidationPolicy == "strict_profile_bound" {
		clientQueue = context.ClientLimitBlock.CarrierMaxQueueDepth
		relayQueue = context.ServerLimitBlock.CarrierMaxQueueDepth
	}
	input := PairInputV1{FirstContactInput: fixture.input, ClientConfig: clientConfig, RelayConfig: relayConfig, ClientControls: ClientLocalRuntimeControlsV1{RuntimeID: "client-runtime", EventCapacity: 128, QueueCeiling: clientQueue}, RelayControls: RelayLocalRuntimeControlsV1{RuntimeID: "relay-runtime", EventCapacity: 128, QueueCeiling: relayQueue}}
	owner := probe
	client, relay, err := owner.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatalf("seed %d pair: %v", seed, err)
	}
	channel, err := newStrictProtectedChannelV1(client, relay)
	if err != nil {
		t.Fatalf("seed %d protected channel: %v", seed, err)
	}
	record, operationID, err := channel.sealClientApplicationV1(1, []byte("wo016-parity"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, ack, err := channel.openClientApplicationV1(record)
	if err != nil || string(plaintext) != "wo016-parity" || ack.OperationID != operationID {
		t.Fatalf("protected round trip: plaintext=%q err=%v", plaintext, err)
	}
	return channel.retainedPolicyTupleV1()
}

func parityRuntimeV1(t *testing.T, fixture strictSupportFixtureV1) *HandshakeRuntime {
	t.Helper()
	runtime := lifecycleRuntimeV1(t, fixture)
	policy := fixture.view.SelectedPolicy
	suite := security.SelectedSuiteV1{KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite}
	for role := 0; role < 2; role++ {
		support := runtime.clientSupport
		if role == 1 {
			support = runtime.relaySupport
		}
		support.transcriptModes = sortedStringsV1(append(support.transcriptModes, policy.TranscriptMode))
		support.downgradePolicies = sortedStringsV1(append(support.downgradePolicies, policy.DowngradePolicy))
		support.capabilityPolicies = sortedStringsV1(append(support.capabilityPolicies, policy.CapabilityNegotiationPolicy))
		support.profilePolicies = sortedStringsV1(append(support.profilePolicies, policy.ProfileCompatibilityPolicy))
		support.configPolicies = sortedStringsV1(append(support.configPolicies, policy.ConfigValidationPolicy))
		support.envelopeModes = sortedStringsV1(append(support.envelopeModes, policy.SecureEnvelopeMode))
		support.suiteTranscriptPairs = append(support.suiteTranscriptPairs, selectedSuiteTranscriptV1{suite: suite, transcriptMode: policy.TranscriptMode})
		for _, binding := range []security.HandshakeModeBinding{fixture.view.ClientModeBinding, fixture.view.ServerModeBinding} {
			capabilities := append([]string(nil), binding.CompatibilityBlock.RequiredCapabilities...)
			capabilities = append(capabilities, binding.ClientOptional...)
			capabilities = append(capabilities, binding.ServerOptional...)
			capabilities = append(capabilities, fixture.view.SelectedCapabilities...)
			support.capabilities = sortedStringsV1(append(support.capabilities, capabilities...))
			support.featureVectors = sortedStringsV1(append(support.featureVectors, binding.FeatureVectors...))
			support.carrierFamilies = sortedStringsV1(append(support.carrierFamilies, binding.CompatibilityBlock.SupportedCarrierFamilies...))
			support.proxyFeatures = sortedStringsV1(append(support.proxyFeatures, binding.CompatibilityBlock.SupportedProxyFeatures...))
			support.streamFeatures = sortedStringsV1(append(support.streamFeatures, binding.CompatibilityBlock.SupportedStreamFeatures...))
			support.adapterClasses = sortedStringsV1(append(support.adapterClasses, binding.LocalAdapterClass))
			support.carrierPolicyHashes = append(support.carrierPolicyHashes, binding.CarrierPolicyHash)
			if binding.EnvelopeLimit > support.maxEnvelopeBytes {
				support.maxEnvelopeBytes = binding.EnvelopeLimit
			}
			if binding.MaxFrameBytes > support.maxFrameBytes {
				support.maxFrameBytes = binding.MaxFrameBytes
			}
			if binding.LimitBlock.CarrierMaxQueueDepth > support.maxQueueDepth {
				support.maxQueueDepth = binding.LimitBlock.CarrierMaxQueueDepth
			}
			if binding.LimitBlock.SessionMaxConcurrentStreams > support.maxStreams {
				support.maxStreams = binding.LimitBlock.SessionMaxConcurrentStreams
			}
			if binding.CompatibilityBlock.MaxReplayWindow > support.maxReplayWindow {
				support.maxReplayWindow = binding.CompatibilityBlock.MaxReplayWindow
			}
		}
		if role == 0 {
			runtime.clientSupport = support
		} else {
			runtime.relaySupport = support
		}
	}
	return runtime
}

func TestGeneratedProfileParityV1(t *testing.T) {
	authorizationPins := parseGeneratedProfileAuthorizationPinsV1(t)
	if len(authorizationPins) != len(generatedProfileParityPinsV1) {
		t.Fatalf("authorization pins=%d matrix rows=%d", len(authorizationPins), len(generatedProfileParityPinsV1))
	}
	parts := make([]string, len(generatedProfileParityPinsV1))
	for i, row := range generatedProfileParityPinsV1 {
		if i > 0 && generatedProfileParityPinsV1[i-1].seed >= row.seed {
			t.Fatal("pin rows not sorted and unique")
		}
		parts[i] = strconv.FormatInt(row.seed, 10)
		if authorizationPins[i].seed != row.seed {
			t.Fatalf("authorization seed=%d matrix seed=%d", authorizationPins[i].seed, row.seed)
		}
		generated, err := compiler.Generate(row.seed)
		if err != nil {
			t.Fatal(err)
		}
		if err := ir.Validate(generated); err != nil {
			t.Fatal(err)
		}
		if got := policyMatrixTupleFromPolicyV1(generated.Security); got != row.tuple {
			t.Fatalf("seed %d generated tuple=%+v want %+v", row.seed, got, row.tuple)
		}
		interpreted := interpretedProfileV1(t, generated, row.tuple)
		if generated == interpreted || &generated.Security == &interpreted.Security {
			t.Fatalf("seed %d interpreted input aliases generated input", row.seed)
		}
		gh, ih := effectiveForProfileV1(t, generated), effectiveForProfileV1(t, interpreted)
		if !reflect.DeepEqual(gh, ih) {
			t.Fatalf("seed %d effective policy parity", row.seed)
		}
		generatedHash, err := security.EffectivePolicyHashV1(gh)
		if err != nil {
			t.Fatal(err)
		}
		interpretedHash, err := security.EffectivePolicyHashV1(ih)
		if err != nil {
			t.Fatal(err)
		}
		pin := authorizationPins[i]
		if generatedHash != interpretedHash || generatedHash != pin.policyHash {
			t.Fatalf("seed %d policy hash parity", row.seed)
		}
		profileHash, err := hex.DecodeString(generated.GenerationHash)
		if err != nil || len(profileHash) != 32 || string(profileHash) != string(pin.profileHash[:]) {
			t.Fatalf("seed %d profile hash pin mismatch", row.seed)
		}
		if uint32(generated.Security.ReplayWindowSize) != pin.replayWindow || uint32(generated.Compatibility.MaxStreamCount) != pin.maxStreams || uint32(generated.Limits.MaxFrameBytes) != pin.maxFrame || uint32(generated.Compatibility.MaxEnvelopeBytes) != pin.maxEnvelope {
			t.Fatalf("seed %d authorization tuple pin mismatch", row.seed)
		}
		generatedFixture := parityFixtureFromPinV1(t, generated, gh, pin)
		interpretedFixture := parityFixtureFromPinV1(t, interpreted, ih, pin)
		if got, want := executePinnedParityChannelV1(t, row.seed, generatedFixture), executePinnedParityChannelV1(t, row.seed, interpretedFixture); got != want || got != row.tuple {
			t.Fatalf("seed %d configured channel mismatch got=%+v want=%+v", row.seed, got, want)
		}
	}
	csv := strings.Join(parts, ",")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(csv))); got != "2577a6114b5df02b44d43ae02fd80fa08f8c593c2449f79a46f84aa63fa5efaa" {
		t.Fatalf("seed CSV hash=%s", got)
	}
}

func TestGeneratedProfileParityMutationCannotSelfAuthorizeV1(t *testing.T) {
	pin := parseGeneratedProfileAuthorizationPinsV1(t)[0]
	profile, err := compiler.Generate(pin.seed)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Security.NonceMode == security.NonceModeCounterAppendBaseV1 {
		profile.Security.NonceMode = security.NonceModeCounterXORBaseV1
	} else {
		profile.Security.NonceMode = security.NonceModeCounterAppendBaseV1
	}
	profile.GenerationHash = ""
	profile.GenerationHash, err = ir.CanonicalHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.Validate(profile); err != nil {
		t.Fatal(err)
	}
	policy := effectiveForProfileV1(t, profile)
	fixture := parityFixtureFromPinV1(t, profile, policy, pin)
	runtime := parityRuntimeV1(t, fixture)
	_, _, err = runtime.strictFirstContactWithContextV1(fixture.input)
	if !errors.Is(err, ErrProfileMismatch) {
		t.Fatalf("mutated generated profile self-authorized: %#v", err)
	}
}
