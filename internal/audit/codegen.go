// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"kurdistan/internal/codegen"
	"kurdistan/internal/observe/diversity"
	"kurdistan/internal/observe/labtrace"
	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/relay"
	"kurdistan/internal/testkit/adversary"
	"kurdistan/internal/testkit/mutant"
)

type CodegenAuditConfig struct {
	Mode       string `json:"mode"`
	OutputPath string `json:"output_path,omitempty"`

	startSeed    int64
	profileCount int
	catalog      codegen.AuthorizationCatalogV1
	provenance   codegenAuditConfigProvenance
}

type codegenAuditConfigProvenance uint8

const (
	codegenAuditConfigProvenanceInvalid codegenAuditConfigProvenance = iota
	codegenAuditConfigProvenanceDefaultV1
	codegenAuditConfigProvenanceExplicitV1
)

// defaultAuthorizationCatalogJSONV1 is the reviewed default_audit_v1 catalog.
// It is compiled into kcheck so the default audit never depends on its cwd or
// on source-tree file discovery.
const (
	defaultAuthorizationCatalogCanonicalBytesV1    = 5250
	defaultAuthorizationCatalogPreCutoverSHA256V1  = "7b96f78a40f64e8736a9b90d727bf2fce755071b87dd9cf86f22b6b425ff0378"
	defaultAuthorizationCatalogPostCutoverSHA256V1 = "92a254bda99d99927bccbb7585cc36f639871132808307b030984f76bca84117"
)

const defaultAuthorizationCatalogJSONV1 = `{
  "version": "profile-authorization-catalog-v1",
  "scope": "default_audit_v1",
  "entries": [
    {
      "seed": 1,
      "client": {
        "profile_hash": "445fb59a74793cb5f864060ed9c3ddb5e557f4f81c55b1e4e7e730c6735ae9a1",
        "effective_policy_hash": "b387522a5e93aa6a0896ddc25181931dd3b7f6db038b2e36acba5af5c768492a",
        "framing_hash": "0ae66add32f46bc5bd7e5ebf713da2bc6e0235d499a1a614b95b52d07c329e32",
        "state_machine_hash": "8d06c12ac250e8ebe2bc285c04d50213e8150f4cb4df63833382311a3ef8b9cf",
        "scheduler_hash": "07153ca5b0e22206e9b45071d304bf611264c2887bea72547452f283cd1734fb",
        "padding_hash": "deccf79ce7692c4a4c1bc26d92202f5f32a2aa280f78fc9c30a1cbf5b8900d71",
        "stream_hash": "51c9145db54640e50ff9ac20748d68594dfa4fc096733d35fb69a6672ccbe466",
        "proxy_hash": "98884a0f1123713765929aada96812c9c2ede81df24f2c524a3db2945ecb2b8f",
        "carrier_context_hash": "0dd7b5e3574b5b96a74b2b04ed75bec5e7e855ac64a42f92afbe7f47fbbad9f8",
        "effective_replay_window": 256,
        "effective_max_concurrent_streams": 8,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 4096
      },
      "relay": {
        "profile_hash": "445fb59a74793cb5f864060ed9c3ddb5e557f4f81c55b1e4e7e730c6735ae9a1",
        "effective_policy_hash": "b387522a5e93aa6a0896ddc25181931dd3b7f6db038b2e36acba5af5c768492a",
        "framing_hash": "0ae66add32f46bc5bd7e5ebf713da2bc6e0235d499a1a614b95b52d07c329e32",
        "state_machine_hash": "8d06c12ac250e8ebe2bc285c04d50213e8150f4cb4df63833382311a3ef8b9cf",
        "scheduler_hash": "07153ca5b0e22206e9b45071d304bf611264c2887bea72547452f283cd1734fb",
        "padding_hash": "deccf79ce7692c4a4c1bc26d92202f5f32a2aa280f78fc9c30a1cbf5b8900d71",
        "stream_hash": "51c9145db54640e50ff9ac20748d68594dfa4fc096733d35fb69a6672ccbe466",
        "proxy_hash": "98884a0f1123713765929aada96812c9c2ede81df24f2c524a3db2945ecb2b8f",
        "carrier_context_hash": "0dd7b5e3574b5b96a74b2b04ed75bec5e7e855ac64a42f92afbe7f47fbbad9f8",
        "effective_replay_window": 256,
        "effective_max_concurrent_streams": 8,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 4096
      }
    },
    {
      "seed": 2,
      "client": {
        "profile_hash": "0ff32f626dcbb105239861caefaf38598004667e5e6993924bd5306fff1a658f",
        "effective_policy_hash": "42a179825dd4ec762fde37dc840f916435e668c3045664ede06c9b5895996087",
        "framing_hash": "ebb01d096febe88778c3b3e5fc237fa0ddbecff8b7bfaf17629594a437b2a7f3",
        "state_machine_hash": "f723a4763d9d1c0e066918b888ec6f270d9693378ba29ebe8d15313c3e3a4f87",
        "scheduler_hash": "1c8137bd52d7db265014821c080d6127336e03ef00704556370db5c8bb9bea80",
        "padding_hash": "3557be6a20ba457aa6b9479d4251cc734a6d160d6fb093d1fbb8e139fef70ffb",
        "stream_hash": "4472ab794385b138666e9c502aea7f30ec15e1ce7f00d55b0b4ab75fc7fcc602",
        "proxy_hash": "1cf883c619cf2888eee47844046887a5569631fc966ea1a77d5c1d553e9055da",
        "carrier_context_hash": "84c8ed71927f31132949943b61a80bc5700c8ae36b20746c18a3b945b01782a6",
        "effective_replay_window": 256,
        "effective_max_concurrent_streams": 4,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 8192
      },
      "relay": {
        "profile_hash": "0ff32f626dcbb105239861caefaf38598004667e5e6993924bd5306fff1a658f",
        "effective_policy_hash": "42a179825dd4ec762fde37dc840f916435e668c3045664ede06c9b5895996087",
        "framing_hash": "ebb01d096febe88778c3b3e5fc237fa0ddbecff8b7bfaf17629594a437b2a7f3",
        "state_machine_hash": "f723a4763d9d1c0e066918b888ec6f270d9693378ba29ebe8d15313c3e3a4f87",
        "scheduler_hash": "1c8137bd52d7db265014821c080d6127336e03ef00704556370db5c8bb9bea80",
        "padding_hash": "3557be6a20ba457aa6b9479d4251cc734a6d160d6fb093d1fbb8e139fef70ffb",
        "stream_hash": "4472ab794385b138666e9c502aea7f30ec15e1ce7f00d55b0b4ab75fc7fcc602",
        "proxy_hash": "1cf883c619cf2888eee47844046887a5569631fc966ea1a77d5c1d553e9055da",
        "carrier_context_hash": "84c8ed71927f31132949943b61a80bc5700c8ae36b20746c18a3b945b01782a6",
        "effective_replay_window": 256,
        "effective_max_concurrent_streams": 4,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 8192
      }
    },
    {
      "seed": 3,
      "client": {
        "profile_hash": "84f477c9c18e4898bfa3b82d1a2918bb18b4d8f88754a743cfef37983c2d50cb",
        "effective_policy_hash": "b66bc2ca56d613beca4eb3e2ed70d0f7cf9eba56b7dbc17f09492d3489444dd5",
        "framing_hash": "e5101002212eec89e8fd408500b1b81c02533e99f05064fe3614118ff3fb9435",
        "state_machine_hash": "66fe8953a74553ee5da8474bc356f06f1aeaee14e3f763e38037a0efe9b6ee40",
        "scheduler_hash": "705fd122ba5db3d30da598786c2c9b46fc2a544ff2c97ce83e7d73c216d815a1",
        "padding_hash": "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36",
        "stream_hash": "42c7570fa3748c02c50c4f06d877f1ec54cd308de0f7678e0a390c18346f9108",
        "proxy_hash": "7c3b5c2cae07f18855deaa592baa9c16f7b3964f38013c57ae4a2e620486ebf2",
        "carrier_context_hash": "631cc5e9350dc5da496086ae71a9e7464e308b6058de977b4c14ce77cda38b37",
        "effective_replay_window": 128,
        "effective_max_concurrent_streams": 8,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 16384
      },
      "relay": {
        "profile_hash": "84f477c9c18e4898bfa3b82d1a2918bb18b4d8f88754a743cfef37983c2d50cb",
        "effective_policy_hash": "b66bc2ca56d613beca4eb3e2ed70d0f7cf9eba56b7dbc17f09492d3489444dd5",
        "framing_hash": "e5101002212eec89e8fd408500b1b81c02533e99f05064fe3614118ff3fb9435",
        "state_machine_hash": "66fe8953a74553ee5da8474bc356f06f1aeaee14e3f763e38037a0efe9b6ee40",
        "scheduler_hash": "705fd122ba5db3d30da598786c2c9b46fc2a544ff2c97ce83e7d73c216d815a1",
        "padding_hash": "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36",
        "stream_hash": "42c7570fa3748c02c50c4f06d877f1ec54cd308de0f7678e0a390c18346f9108",
        "proxy_hash": "7c3b5c2cae07f18855deaa592baa9c16f7b3964f38013c57ae4a2e620486ebf2",
        "carrier_context_hash": "631cc5e9350dc5da496086ae71a9e7464e308b6058de977b4c14ce77cda38b37",
        "effective_replay_window": 128,
        "effective_max_concurrent_streams": 8,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 16384
      }
    },
    {
      "seed": 4,
      "client": {
        "profile_hash": "6bb5a39a97828f8e097d2a5dcb244a252bf49e325de8c793ea39fe55e94df980",
        "effective_policy_hash": "3d3ef057e66ff5ad987b58fc74a9b52567f3186a9b179119bddbe940bf13c4fa",
        "framing_hash": "a404d7d81b493e9e0ddbafc9dd07c895c9bae818ddb968eeb5a2ccff0c65114f",
        "state_machine_hash": "88c3af31edfa765f6aebbf8fe175dc3123942717168deb2b57d85c301dafec07",
        "scheduler_hash": "e15120dff28f5737aab3ee3f4a1364ad169c70bb9e9575cc9f824ab41860c4f3",
        "padding_hash": "c7b513c2ed5bc56ec3c606564f60b8a0499de02a79b157123834ad227a8d1fb5",
        "stream_hash": "4bc9313a861fc783ef303d7c35db343cd58bffa0cfe078ce212bce76bc4ba392",
        "proxy_hash": "634aed170481afedd2ca39bdbbaf64fdfb61e2369126195c3d85dc9559e23eb9",
        "carrier_context_hash": "a873072eaaf9d2b34c6d1dd4e996c73dd75f4dca2afe7c33d4fe9cc45fc76634",
        "effective_replay_window": 128,
        "effective_max_concurrent_streams": 8,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 1024
      },
      "relay": {
        "profile_hash": "6bb5a39a97828f8e097d2a5dcb244a252bf49e325de8c793ea39fe55e94df980",
        "effective_policy_hash": "3d3ef057e66ff5ad987b58fc74a9b52567f3186a9b179119bddbe940bf13c4fa",
        "framing_hash": "a404d7d81b493e9e0ddbafc9dd07c895c9bae818ddb968eeb5a2ccff0c65114f",
        "state_machine_hash": "88c3af31edfa765f6aebbf8fe175dc3123942717168deb2b57d85c301dafec07",
        "scheduler_hash": "e15120dff28f5737aab3ee3f4a1364ad169c70bb9e9575cc9f824ab41860c4f3",
        "padding_hash": "c7b513c2ed5bc56ec3c606564f60b8a0499de02a79b157123834ad227a8d1fb5",
        "stream_hash": "4bc9313a861fc783ef303d7c35db343cd58bffa0cfe078ce212bce76bc4ba392",
        "proxy_hash": "634aed170481afedd2ca39bdbbaf64fdfb61e2369126195c3d85dc9559e23eb9",
        "carrier_context_hash": "a873072eaaf9d2b34c6d1dd4e996c73dd75f4dca2afe7c33d4fe9cc45fc76634",
        "effective_replay_window": 128,
        "effective_max_concurrent_streams": 8,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 1024
      }
    },
    {
      "seed": 5,
      "client": {
        "profile_hash": "8ad255f0573af59d010d6873f5d357de1532cc55db2c5be75bb0607b23810e7f",
        "effective_policy_hash": "9caf18ee76b28cc949c1a73951d3a8df14e0a32c73f2a919f9e6a54fde49f05c",
        "framing_hash": "5d291b836b5581951766c9a391e358aaa9071339b4efd3cc2b8ecad125703ea2",
        "state_machine_hash": "4295a75b5767a4b453a3cee715006065afe7bc2a779bf3348e7ff1bbf2942975",
        "scheduler_hash": "2e2e244351808654020f86ea4052d6e7e26939756f2690d77cb1ef6163f78f8a",
        "padding_hash": "b1e465202ecac129b48731f39441e7ac294ccc8097e52d03abacfb27e1f8ad22",
        "stream_hash": "d901cdaf9c2b0ce2751063283c4cd1f9476bddb67750fbf5a183a8a342d80cd2",
        "proxy_hash": "d3620ea9a3421c472cc393d70045b518a0a119ec585d4a50cbb881e8005a4e04",
        "carrier_context_hash": "a97ecc282b30560ce61e4351d42e4b1ab7ba710a0d4408ed278fd13cee588b21",
        "effective_replay_window": 256,
        "effective_max_concurrent_streams": 2,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 8192
      },
      "relay": {
        "profile_hash": "8ad255f0573af59d010d6873f5d357de1532cc55db2c5be75bb0607b23810e7f",
        "effective_policy_hash": "9caf18ee76b28cc949c1a73951d3a8df14e0a32c73f2a919f9e6a54fde49f05c",
        "framing_hash": "5d291b836b5581951766c9a391e358aaa9071339b4efd3cc2b8ecad125703ea2",
        "state_machine_hash": "4295a75b5767a4b453a3cee715006065afe7bc2a779bf3348e7ff1bbf2942975",
        "scheduler_hash": "2e2e244351808654020f86ea4052d6e7e26939756f2690d77cb1ef6163f78f8a",
        "padding_hash": "b1e465202ecac129b48731f39441e7ac294ccc8097e52d03abacfb27e1f8ad22",
        "stream_hash": "d901cdaf9c2b0ce2751063283c4cd1f9476bddb67750fbf5a183a8a342d80cd2",
        "proxy_hash": "d3620ea9a3421c472cc393d70045b518a0a119ec585d4a50cbb881e8005a4e04",
        "carrier_context_hash": "a97ecc282b30560ce61e4351d42e4b1ab7ba710a0d4408ed278fd13cee588b21",
        "effective_replay_window": 256,
        "effective_max_concurrent_streams": 2,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 8192
      }
    },
    {
      "seed": 6,
      "client": {
        "profile_hash": "f84ba1cf9104dc28ef5d42c4661805a31e146772a88eb454b44fd9184b47b071",
        "effective_policy_hash": "8c73808f506cda6fad07714b0cebcf8b4eb661e3de679d776489f341a0e56bae",
        "framing_hash": "de89d310204a95faf52bc7b2e367ebb75c1861ad8aaea14a5adacdb5a4bd0ab8",
        "state_machine_hash": "1b263804934f8e9f4e4f0d0ca9d099ef3ec5db1cc442c67910213155b5a7bbae",
        "scheduler_hash": "a804c36f77da40a078a5431ea751ce88d96c95f58f51755e1b77e39c6c3b36fc",
        "padding_hash": "85d958e5cf2fc9fe3018aaa3f52729aaf183d63b27cbad907288a3fbf96db27e",
        "stream_hash": "2eb2204a62244eead363ec74e055e3b055582d7570b221d38ede10d98fead3fc",
        "proxy_hash": "d94c698a6c0149d0de43263a3953a236beab62da4d5423f2d384ae7caff5b2d5",
        "carrier_context_hash": "4811c14fcd09171b26b280646d2f62cd6812e102cc10aa04b274b9b8948abd85",
        "effective_replay_window": 32,
        "effective_max_concurrent_streams": 16,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 1024
      },
      "relay": {
        "profile_hash": "f84ba1cf9104dc28ef5d42c4661805a31e146772a88eb454b44fd9184b47b071",
        "effective_policy_hash": "8c73808f506cda6fad07714b0cebcf8b4eb661e3de679d776489f341a0e56bae",
        "framing_hash": "de89d310204a95faf52bc7b2e367ebb75c1861ad8aaea14a5adacdb5a4bd0ab8",
        "state_machine_hash": "1b263804934f8e9f4e4f0d0ca9d099ef3ec5db1cc442c67910213155b5a7bbae",
        "scheduler_hash": "a804c36f77da40a078a5431ea751ce88d96c95f58f51755e1b77e39c6c3b36fc",
        "padding_hash": "85d958e5cf2fc9fe3018aaa3f52729aaf183d63b27cbad907288a3fbf96db27e",
        "stream_hash": "2eb2204a62244eead363ec74e055e3b055582d7570b221d38ede10d98fead3fc",
        "proxy_hash": "d94c698a6c0149d0de43263a3953a236beab62da4d5423f2d384ae7caff5b2d5",
        "carrier_context_hash": "4811c14fcd09171b26b280646d2f62cd6812e102cc10aa04b274b9b8948abd85",
        "effective_replay_window": 32,
        "effective_max_concurrent_streams": 16,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 1024
      }
    },
    {
      "seed": 7,
      "client": {
        "profile_hash": "d61bd97c1d3d4eefe3f93e64c7132750dc96ec566373f4a7906bcce8bbe4d21b",
        "effective_policy_hash": "caaacf48e81a01f6fa195d5c6e49d0a390066a16fa3a6ee48f8672765a6ef8f9",
        "framing_hash": "13892230a03796b7b501bd8c3c61115764627faf34972a5f0eb2472439146a49",
        "state_machine_hash": "e7e8a0f04b82a4f0457d88d9b0739092f9913a6c41ffc5e92289d10b38c5e757",
        "scheduler_hash": "578e1b56dfafb0c0464b04fe8e0621a3a37a005ab1bdce35a1cfae111fefe0f5",
        "padding_hash": "e30b6cbfcc447dfed9098a59f79fa442d52db5242da925ff4ec814234435ada8",
        "stream_hash": "a7cf1c53a2660c28c913f5b4d9021c0848fd1389c45eb0798f09bc62a88a98e8",
        "proxy_hash": "7d3318e127022dae6d4bdfbaf34586ec8f7ae6f820ea8c8477ced9541266c998",
        "carrier_context_hash": "579e25c59bffbb99b006a9158b0b6691a04731f239fce28ff8103a3cbfdb4723",
        "effective_replay_window": 128,
        "effective_max_concurrent_streams": 4,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 4096
      },
      "relay": {
        "profile_hash": "d61bd97c1d3d4eefe3f93e64c7132750dc96ec566373f4a7906bcce8bbe4d21b",
        "effective_policy_hash": "caaacf48e81a01f6fa195d5c6e49d0a390066a16fa3a6ee48f8672765a6ef8f9",
        "framing_hash": "13892230a03796b7b501bd8c3c61115764627faf34972a5f0eb2472439146a49",
        "state_machine_hash": "e7e8a0f04b82a4f0457d88d9b0739092f9913a6c41ffc5e92289d10b38c5e757",
        "scheduler_hash": "578e1b56dfafb0c0464b04fe8e0621a3a37a005ab1bdce35a1cfae111fefe0f5",
        "padding_hash": "e30b6cbfcc447dfed9098a59f79fa442d52db5242da925ff4ec814234435ada8",
        "stream_hash": "a7cf1c53a2660c28c913f5b4d9021c0848fd1389c45eb0798f09bc62a88a98e8",
        "proxy_hash": "7d3318e127022dae6d4bdfbaf34586ec8f7ae6f820ea8c8477ced9541266c998",
        "carrier_context_hash": "579e25c59bffbb99b006a9158b0b6691a04731f239fce28ff8103a3cbfdb4723",
        "effective_replay_window": 128,
        "effective_max_concurrent_streams": 4,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 4096
      }
    },
    {
      "seed": 8,
      "client": {
        "profile_hash": "b516ccbb737785f3e136a490f735ca72b229071d43763649c4e23af71b70bfe4",
        "effective_policy_hash": "647c10cfa102c6efb1e1f0cddd5f71ddd4481d6248bd67ede4bf411b3b8016bc",
        "framing_hash": "0e7d3e803f9a17ccd60e06bd1c4b76d3a2ef460f515a910693e2be044d003392",
        "state_machine_hash": "4db3f33d7cdd7d79038bfc7efac0320f2aa2a2b713e606c6655c41f20053259c",
        "scheduler_hash": "b6de36b9ce63c1d40236018fb777942fcf4e949d8f157bff0901ca8bfff5062e",
        "padding_hash": "0c7a1d259d28d6d9dc2d04473df34866f5441cd5f8c30750419b433dd79cd783",
        "stream_hash": "10afc6c96d2f1105a0ce085fa0234079eccbd0432f74b296ca9ff8a11cd6eaa7",
        "proxy_hash": "617c226cf14fd71e4c2e149ad27459b30979f16f653985fe8f3449fcfa0ed15b",
        "carrier_context_hash": "42e27da93791f2725b50d7f5422dd0a2b7f36715cf5740aad27ab0fa4826dca6",
        "effective_replay_window": 64,
        "effective_max_concurrent_streams": 16,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 2048
      },
      "relay": {
        "profile_hash": "b516ccbb737785f3e136a490f735ca72b229071d43763649c4e23af71b70bfe4",
        "effective_policy_hash": "647c10cfa102c6efb1e1f0cddd5f71ddd4481d6248bd67ede4bf411b3b8016bc",
        "framing_hash": "0e7d3e803f9a17ccd60e06bd1c4b76d3a2ef460f515a910693e2be044d003392",
        "state_machine_hash": "4db3f33d7cdd7d79038bfc7efac0320f2aa2a2b713e606c6655c41f20053259c",
        "scheduler_hash": "b6de36b9ce63c1d40236018fb777942fcf4e949d8f157bff0901ca8bfff5062e",
        "padding_hash": "0c7a1d259d28d6d9dc2d04473df34866f5441cd5f8c30750419b433dd79cd783",
        "stream_hash": "10afc6c96d2f1105a0ce085fa0234079eccbd0432f74b296ca9ff8a11cd6eaa7",
        "proxy_hash": "617c226cf14fd71e4c2e149ad27459b30979f16f653985fe8f3449fcfa0ed15b",
        "carrier_context_hash": "42e27da93791f2725b50d7f5422dd0a2b7f36715cf5740aad27ab0fa4826dca6",
        "effective_replay_window": 64,
        "effective_max_concurrent_streams": 16,
        "effective_max_frame_bytes": 65536,
        "effective_max_envelope_bytes": 2048
      }
    }
  ]
}
`

type GeneratedBackendTraceCorpus struct {
	ProfileCount                 int                       `json:"profile_count"`
	GeneratedModules             int                       `json:"generated_modules"`
	ProfileRuns                  []GeneratedBackendRun     `json:"profile_runs"`
	SourceScan                   codegen.SourceScanReport  `json:"source_scan"`
	InterpretedTraces            [][]ktrace.Event          `json:"-"`
	GeneratedTraces              [][]ktrace.Event          `json:"-"`
	InterpretedMultiStreamTraces [][]ktrace.Event          `json:"-"`
	GeneratedMultiStreamTraces   [][]ktrace.Event          `json:"-"`
	GeneratedDirs                []string                  `json:"-"`
	Profiles                     []*GeneratedProfileRecord `json:"profiles,omitempty"`
}

type GeneratedProfileRecord struct {
	ProfileID string `json:"profile_id"`
	Seed      int64  `json:"seed"`
}

type GeneratedBackendRun struct {
	ProfileID                     string  `json:"profile_id"`
	Seed                          int64   `json:"seed"`
	GeneratedEchoBytes            int     `json:"generated_echo_bytes"`
	InterpretedEchoBytes          int     `json:"interpreted_echo_bytes"`
	InterpretedFirstContactCount  int     `json:"interpreted_first_contact_count"`
	GeneratedFirstContactCount    int     `json:"generated_first_contact_count"`
	InterpretedDataEvents         int     `json:"interpreted_data_events"`
	GeneratedDataEvents           int     `json:"generated_data_events"`
	SemanticSimilarity            float64 `json:"semantic_similarity"`
	StatePathSimilarity           float64 `json:"state_path_similarity"`
	SemanticEquivalent            bool    `json:"semantic_equivalent"`
	InterpretedMultiStreamEvents  int     `json:"interpreted_multi_stream_events"`
	GeneratedMultiStreamEvents    int     `json:"generated_multi_stream_events"`
	GeneratedMultiStreamEchoBytes int     `json:"generated_multi_stream_echo_bytes"`
	MultiStreamEquivalent         bool    `json:"multi_stream_equivalent"`
	PayloadLogged                 bool    `json:"payload_logged"`
}

type GeneratedTraceSummary struct {
	ProfileID         string `json:"profile_id"`
	EchoBytes         int    `json:"echo_bytes"`
	EventCount        int    `json:"event_count"`
	FirstContactCount int    `json:"first_contact_count"`
	DataEventCount    int    `json:"data_event_count"`
	RelayReadyEvents  int    `json:"relay_ready_events"`
	PayloadLogged     bool   `json:"payload_logged"`
}

type CodegenAuditSummary struct {
	Profiles                         int                            `json:"profiles"`
	GeneratedModules                 int                            `json:"generated_modules"`
	SemanticEquivalence              string                         `json:"semantic_equivalence"`
	GeneratedProfileDiversity        string                         `json:"generated_profile_diversity"`
	FixedSignature                   string                         `json:"fixed_signature"`
	MutantDetection                  string                         `json:"mutant_detection"`
	MultiStreamGeneratedParity       string                         `json:"multi_stream_generated_parity"`
	StreamAdversaryParity            string                         `json:"multi_stream_generated_backend_parity"`
	ProxySemGeneratedParity          string                         `json:"proxy_generated_backend_parity"`
	CarrierGeneratedParity           string                         `json:"carrier_generated_backend_parity"`
	SecurityGeneratedParity          string                         `json:"security_generated_backend_parity"`
	RuntimeGeneratedParity           string                         `json:"runtime_generated_backend_parity"`
	HardeningGeneratedParity         string                         `json:"hardening_generated_backend_parity"`
	AdapterGeneratedParity           string                         `json:"adapter_generated_backend_parity"`
	LocalAdapterGeneratedParity      string                         `json:"local_adapter_generated_backend_parity"`
	ByteTransportGeneratedParity     string                         `json:"byte_transport_generated_backend_parity"`
	BytePathFixtureParity            string                         `json:"bytepath_fixture_generated_backend_parity"`
	WireFeaturesGeneratedParity      string                         `json:"wirefeatures_generated_backend_parity"`
	WireGenGeneratedParity           string                         `json:"wiregen_generated_backend_parity"`
	HostDetectGeneratedParity        string                         `json:"hostdetect_generated_backend_parity"`
	RelayFleetGeneratedParity        string                         `json:"relayfleet_generated_backend_parity"`
	ProxyIngressGeneratedParity      string                         `json:"proxyingress_generated_backend_parity"`
	LocalProxyIngressGeneratedParity string                         `json:"localproxyingress_generated_backend_parity"`
	LocalProxyIngressAdvParity       string                         `json:"localproxyingressadv_generated_backend_parity"`
	AdaptivePathGeneratedParity      string                         `json:"adaptivepath_generated_backend_parity"`
	TransportBundleGeneratedParity   string                         `json:"transportbundle_generated_backend_parity"`
	PathRaceGeneratedParity          string                         `json:"pathrace_generated_backend_parity"`
	PathHealthGeneratedParity        string                         `json:"pathhealth_generated_backend_parity"`
	CarrierReviewGeneratedParity     string                         `json:"carrierreview_generated_backend_parity"`
	MeasurementReviewGeneratedParity string                         `json:"measurementreview_generated_backend_parity"`
	ProxyEgressGeneratedParity       string                         `json:"proxyegress_generated_backend_parity"`
	RelayBridgeGeneratedParity       string                         `json:"relaybridge_generated_backend_parity"`
	LocalPipelineGeneratedParity     string                         `json:"localpipeline_generated_backend_parity"`
	ProductionReadinessParity        string                         `json:"productionreadiness_generated_backend_parity"`
	ConcreteLocalAdapterParity       string                         `json:"concretelocaladapter_generated_backend_parity"`
	LocalProtocolAdapterParity       string                         `json:"localprotocoladapter_generated_backend_parity"`
	LoopbackRelayParity              string                         `json:"loopbackrelay_generated_backend_parity"`
	LabEgressParity                  string                         `json:"labegress_generated_backend_parity"`
	CarrierReadinessParity           string                         `json:"carrierreadiness_generated_backend_parity"`
	HTTPSCarrierReviewParity         string                         `json:"httpscarrierreview_generated_backend_parity"`
	HTTPSLikeCarrierParity           string                         `json:"httpslikecarrier_generated_backend_parity"`
	HTTPSCarrierAdversaryParity      string                         `json:"httpscarrieradversary_generated_backend_parity"`
	ConstrainedCarrierReviewParity   string                         `json:"constrainedcarrierreview_generated_backend_parity"`
	ConstrainedCarrierParity         string                         `json:"constrainedcarrier_generated_backend_parity"`
	MultiCarrierSelectParity         string                         `json:"multicarrierselect_generated_backend_parity"`
	CarrierCollapseParity            string                         `json:"carriercollapse_generated_backend_parity"`
	LocalProxyAdapterReviewParity    string                         `json:"localproxyadapterreview_generated_backend_parity"`
	LocalProxyAdapterParity          string                         `json:"localproxyadapter_generated_backend_parity"`
	VPNSemanticsParity               string                         `json:"vpnsemantics_generated_backend_parity"`
	LocalVPNAdapterParity            string                         `json:"localvpnadapter_generated_backend_parity"`
	RelayProcessParity               string                         `json:"relayprocess_generated_backend_parity"`
	KeyExchangePlanParity            string                         `json:"keyexchangeplan_generated_backend_parity"`
	RelayAuthPlanParity              string                         `json:"relayauthplan_generated_backend_parity"`
	OperationalHardeningParity       string                         `json:"operationalhardening_generated_backend_parity"`
	AndroidReviewParity              string                         `json:"androidreview_generated_backend_parity"`
	AndroidRuntimeParity             string                         `json:"androidruntime_generated_backend_parity"`
	AndroidVPNServiceParity          string                         `json:"androidvpnservice_generated_backend_parity"`
	AndroidCarrierParity             string                         `json:"androidcarrier_generated_backend_parity"`
	SourceScanner                    string                         `json:"source_scanner"`
	InterpretedVsGenerated           InterpretedGeneratedDivergence `json:"interpreted_vs_generated"`
	SourceScan                       codegen.SourceScanReport       `json:"source_scan"`
	LegacyEvidenceClass              string                         `json:"legacy_evidence_class"`
}

type InterpretedGeneratedDivergence struct {
	SameProfileSemanticSimilarityAverage float64 `json:"same_profile_semantic_similarity_average"`
	SameProfileTraceSimilarityAverage    float64 `json:"same_profile_trace_similarity_average"`
	GeneratedDifferentProfileDiversity   float64 `json:"generated_different_profile_diversity"`
	InterpretedDifferentProfileDiversity float64 `json:"interpreted_different_profile_diversity"`
	Assessment                           string  `json:"assessment"`
}

func DefaultCodegenAuditConfig(mode string) CodegenAuditConfig {
	if mode == "" {
		mode = "quick"
	}
	catalog, err := codegen.ParseAuthorizationCatalogV1([]byte(defaultAuthorizationCatalogJSONV1))
	if err != nil || catalog.ValidateExactSeedRangeV1(codegen.AuthorizationCatalogScopeDefaultAuditV1, 1, 8) != nil {
		return CodegenAuditConfig{Mode: mode}
	}
	cfg := CodegenAuditConfig{Mode: mode, startSeed: 1, profileCount: 3, catalog: catalog, provenance: codegenAuditConfigProvenanceDefaultV1}
	if mode == "full" {
		cfg.profileCount = 8
	}
	return cfg
}

func NewExplicitCodegenAuditConfig(mode string, startSeed int64, profileCount int, catalog codegen.AuthorizationCatalogV1) (CodegenAuditConfig, error) {
	if mode == "" {
		mode = "quick"
	}
	if strictCodegenRangeValid(startSeed, profileCount) != nil {
		return CodegenAuditConfig{}, codegen.ErrStrictSeedRange
	}
	if err := catalog.ValidateExactSeedRangeV1(codegen.AuthorizationCatalogScopeExplicitV1, startSeed, profileCount); err != nil {
		return CodegenAuditConfig{}, codegen.ErrAuthorizationCatalogInvalid
	}
	return CodegenAuditConfig{Mode: mode, startSeed: startSeed, profileCount: profileCount, catalog: catalog, provenance: codegenAuditConfigProvenanceExplicitV1}, nil

}

func NormalizeCodegenAuditConfig(cfg CodegenAuditConfig) (CodegenAuditConfig, error) {
	if cfg.Mode == "" || cfg.profileCount <= 0 || strictCodegenRangeValid(cfg.startSeed, cfg.profileCount) != nil {
		return CodegenAuditConfig{}, codegen.ErrStrictSeedRange
	}
	scope := ""
	switch cfg.provenance {
	case codegenAuditConfigProvenanceDefaultV1:
		scope = codegen.AuthorizationCatalogScopeDefaultAuditV1
		if cfg.startSeed != 1 || cfg.profileCount != 3 && cfg.profileCount != 8 {
			return CodegenAuditConfig{}, codegen.ErrAuthorizationCatalogInvalid
		}
		if err := cfg.catalog.ValidateExactSeedRangeV1(scope, 1, 8); err != nil {
			return CodegenAuditConfig{}, codegen.ErrAuthorizationCatalogInvalid
		}
		return cfg, nil
	case codegenAuditConfigProvenanceExplicitV1:
		scope = codegen.AuthorizationCatalogScopeExplicitV1
	default:
		return CodegenAuditConfig{}, codegen.ErrAuthorizationCatalogInvalid
	}
	if err := cfg.catalog.ValidateExactSeedRangeV1(scope, cfg.startSeed, cfg.profileCount); err != nil {
		return CodegenAuditConfig{}, codegen.ErrAuthorizationCatalogInvalid
	}
	return cfg, nil
}

func strictCodegenRangeValid(startSeed int64, profileCount int) error {
	if profileCount <= 0 || profileCount > 512 || startSeed > math.MaxInt64-7-int64(profileCount-1) {
		return codegen.ErrStrictSeedRange
	}
	return nil
}

func RunCodegenAudit(ctx context.Context, cfg CodegenAuditConfig) (AuditReport, error) {
	var err error
	cfg, err = NormalizeCodegenAuditConfig(cfg)
	if err != nil {
		return AuditReport{}, err
	}
	start := time.Now()
	root, err := os.MkdirTemp("", "kurdistan-codegen-audit-*")
	if err != nil {
		return AuditReport{}, err
	}
	defer os.RemoveAll(root)

	corpus, err := runGeneratedBackendTraceCorpusAt(ctx, cfg, root)
	if err != nil {
		return AuditReport{}, err
	}

	testFailures := []string{}
	for _, dir := range corpus.GeneratedDirs {
		output, err := runGoTest(ctx, dir)
		if err != nil {
			testFailures = append(testFailures, fmt.Sprintf("%s generated go test failed: %v\n%s", filepath.Base(dir), err, trimOutput(output)))
		}
	}
	codegenGate := gate("generated_backend_codegen", len(testFailures) == 0, "required", fmt.Sprintf("%d generated modules checked; %d failures", corpus.GeneratedModules, len(testFailures)), map[string]any{
		"generated_module_count":     corpus.GeneratedModules,
		"generated_tests_run":        len(corpus.GeneratedDirs),
		"interpreted_traces_checked": len(corpus.InterpretedTraces),
		"generated_traces_checked":   len(corpus.GeneratedTraces),
		"round_trip_exercised_by":    "generated-trace command and generated protocol tests",
	}, testFailures)
	semanticGate := GeneratedSemanticEquivalenceGate(corpus)
	diversityGate := GeneratedProfileDiversityGate(corpus)
	fixedGate := GeneratedFixedSignatureGate(corpus)
	divergenceGate := GeneratedVsInterpretedDivergenceGate(corpus)
	multiStreamGate := GeneratedMultiStreamParityGate(corpus)
	streamAdversaryGate := GeneratedStreamAdversaryParityGate(corpus, testFailures)
	proxySemGate := GeneratedProxySemParityGate(corpus, testFailures)
	carrierGate := GeneratedCarrierParityGate(corpus, testFailures)
	securityGate := GeneratedSecurityParityGate(corpus, testFailures)
	runtimeGate := GeneratedRuntimeParityGate(corpus, testFailures)
	hardeningGate := GeneratedHardeningParityGate(corpus, testFailures)
	adapterGate := GeneratedAdapterParityGate(corpus, testFailures)
	localAdapterGate := GeneratedLocalAdapterParityGate(corpus, testFailures)
	byteTransportGate := GeneratedByteTransportParityGate(corpus, testFailures)
	bytePathFixtureGate := GeneratedBytePathFixtureParityGate(corpus, testFailures)
	wireFeaturesGate := WireFeaturesGeneratedBackendParityGate()
	wireGenGate := WireGenGeneratedBackendParityGate()
	hostDetectGate := HostDetectGeneratedBackendParityGate()
	relayFleetGate := RelayFleetGeneratedBackendParityGate()
	proxyIngressGate := GeneratedProxyIngressParityGate(corpus, testFailures)
	localProxyIngressGate := GeneratedLocalProxyIngressParityGate(corpus, testFailures)
	localProxyIngressAdvGate := GeneratedLocalProxyIngressAdvParityGate(corpus, testFailures)
	adaptivePathGate := GeneratedAdaptivePathParityGate(corpus, testFailures)
	transportBundleGate := GeneratedTransportBundleParityGate(corpus, testFailures)
	pathRaceGate := GeneratedPathRaceParityGate(corpus, testFailures)
	pathHealthGate := GeneratedPathHealthParityGate(corpus, testFailures)
	carrierReviewGate := GeneratedCarrierReviewParityGate(corpus, testFailures)
	measurementReviewGate := GeneratedMeasurementReviewParityGate(corpus, testFailures)
	proxyEgressGate := GeneratedProxyEgressParityGate(corpus, testFailures)
	relayBridgeGate := GeneratedRelayBridgeParityGate(corpus, testFailures)
	localPipelineGate := GeneratedLocalPipelineParityGate(corpus, testFailures)
	productionReadinessGate := GeneratedProductionReadinessParityGate(corpus, testFailures)
	concreteLocalAdapterGate := GeneratedConcreteLocalAdapterParityGate(corpus, testFailures)
	localProtocolAdapterGate := GeneratedLocalProtocolAdapterParityGate(corpus, testFailures)
	loopbackRelayGate := GeneratedLoopbackRelayParityGate(corpus, testFailures)
	labEgressGate := GeneratedLabEgressParityGate(corpus, testFailures)
	carrierReadinessGate := GeneratedCarrierReadinessParityGate(corpus, testFailures)
	httpsCarrierReviewGate := GeneratedHTTPSCarrierReviewParityGate(corpus, testFailures)
	httpsLikeCarrierGate := GeneratedHTTPSLikeCarrierParityGate(corpus, testFailures)
	httpsCarrierAdversaryGate := GeneratedHTTPSCarrierAdversaryParityGate(corpus, testFailures)
	constrainedCarrierReviewGate := GeneratedConstrainedCarrierReviewParityGate(corpus, testFailures)
	constrainedCarrierGate := GeneratedConstrainedCarrierParityGate(corpus, testFailures)
	multiCarrierSelectGate := GeneratedMultiCarrierSelectParityGate(corpus, testFailures)
	carrierCollapseGate := GeneratedCarrierCollapseParityGate(corpus, testFailures)
	localProxyAdapterReviewGate := GeneratedLocalProxyAdapterReviewParityGate(corpus, testFailures)
	localProxyAdapterGate := GeneratedLocalProxyAdapterParityGate(corpus, testFailures)
	vpnSemanticsGate := GeneratedVPNSemanticsParityGate(corpus, testFailures)
	localVPNAdapterGate := GeneratedLocalVPNAdapterParityGate(corpus, testFailures)
	relayProcessGate := GeneratedRelayProcessParityGate(corpus, testFailures)
	keyExchangePlanGate := GeneratedKeyExchangePlanParityGate(corpus, testFailures)
	relayAuthPlanGate := GeneratedRelayAuthPlanParityGate(corpus, testFailures)
	operationalHardeningGate := GeneratedOperationalHardeningParityGate(corpus, testFailures)
	androidReviewGate := GeneratedAndroidReviewParityGate(corpus, testFailures)
	androidRuntimeGate := GeneratedAndroidRuntimeParityGate(corpus, testFailures)
	androidVPNServiceGate := GeneratedAndroidVPNServiceParityGate(corpus, testFailures)
	androidCarrierGate := GeneratedAndroidCarrierParityGate(corpus, testFailures)
	mutantGate := GeneratedMutantDetectionGate(ctx, []string{
		mutant.ModeCosmeticSymbolsOnly,
		mutant.ModeFixedFrameGrammar,
		mutant.ModeFixedFirstContact,
		mutant.ModePaddingNoiseOnly,
	}, max(4, min(8, cfg.profileCount)))
	scannerGate := GeneratedSourceScannerGate(corpus.SourceScan)

	gates := []GateResult{
		codegenGate,
		semanticGate,
		diversityGate,
		fixedGate,
		divergenceGate,
		multiStreamGate,
		streamAdversaryGate,
		proxySemGate,
		carrierGate,
		securityGate,
		runtimeGate,
		hardeningGate,
		adapterGate,
		localAdapterGate,
		byteTransportGate,
		bytePathFixtureGate,
		wireFeaturesGate,
		wireGenGate,
		hostDetectGate,
		relayFleetGate,
		proxyIngressGate,
		localProxyIngressGate,
		localProxyIngressAdvGate,
		adaptivePathGate,
		transportBundleGate,
		pathRaceGate,
		pathHealthGate,
		carrierReviewGate,
		measurementReviewGate,
		proxyEgressGate,
		relayBridgeGate,
		localPipelineGate,
		productionReadinessGate,
		concreteLocalAdapterGate,
		localProtocolAdapterGate,
		loopbackRelayGate,
		labEgressGate,
		carrierReadinessGate,
		httpsCarrierReviewGate,
		httpsLikeCarrierGate,
		httpsCarrierAdversaryGate,
		constrainedCarrierReviewGate,
		constrainedCarrierGate,
		multiCarrierSelectGate,
		carrierCollapseGate,
		localProxyAdapterReviewGate,
		localProxyAdapterGate,
		vpnSemanticsGate,
		localVPNAdapterGate,
		relayProcessGate,
		keyExchangePlanGate,
		relayAuthPlanGate,
		operationalHardeningGate,
		androidReviewGate,
		androidRuntimeGate,
		androidVPNServiceGate,
		androidCarrierGate,
		mutantGate,
		scannerGate,
	}
	report := AuditReport{
		Version:          codegen.Version,
		Mode:             "codegen-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.profileCount,
		TraceCount:       len(corpus.GeneratedTraces),
		Gates:            gates,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
		CodegenSummary:   buildCodegenSummary(corpus, gates),
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func RunGeneratedBackendTraceCorpus(ctx context.Context, cfg CodegenAuditConfig) (GeneratedBackendTraceCorpus, error) {
	var err error
	cfg, err = NormalizeCodegenAuditConfig(cfg)
	if err != nil {
		return GeneratedBackendTraceCorpus{}, err
	}
	root, err := os.MkdirTemp("", "kurdistan-codegen-corpus-*")
	if err != nil {
		return GeneratedBackendTraceCorpus{}, err
	}
	defer os.RemoveAll(root)
	return runGeneratedBackendTraceCorpusAt(ctx, cfg, root)
}

func runGeneratedBackendTraceCorpusAt(ctx context.Context, cfg CodegenAuditConfig, root string) (GeneratedBackendTraceCorpus, error) {
	payload := codegenAuditPayload()
	corpus := GeneratedBackendTraceCorpus{ProfileCount: cfg.profileCount}
	profilesForScan := make([]string, 0, cfg.profileCount)
	for i := 0; i < cfg.profileCount; i++ {
		seed := cfg.startSeed + int64(i)
		p, err := compiler.Generate(seed)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d profile generation: %w", seed, err)
		}
		out := filepath.Join(root, codegen.SanitizeIdentifier(p.ID))
		if _, err := codegen.GenerateStrict(p, out, codegen.Options{}, cfg.catalog); err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d codegen: %w", seed, err)
		}
		interpreted, err := labtrace.CaptureTrace(ctx, p, payload)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d interpreted trace: %w", seed, err)
		}
		generated, summary, err := runGeneratedTraceCommand(ctx, out, payload, false)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d generated trace: %w", seed, err)
		}
		streamCount := min(4, p.Stream.MaxConcurrentStreams)
		interpretedMultiResult, interpretedMulti, err := relay.SimulateMultiStreamEcho(ctx, p, relay.DefaultMultiStreamDemoRequests(streamCount))
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d interpreted multistream trace: %w", seed, err)
		}
		generatedMulti, multiSummary, err := runGeneratedTraceCommand(ctx, out, nil, true)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d generated multistream trace: %w", seed, err)
		}
		report := ktrace.CompareEvents(interpreted, generated)
		run := GeneratedBackendRun{
			ProfileID:                     p.ID,
			Seed:                          seed,
			GeneratedEchoBytes:            summary.EchoBytes,
			InterpretedEchoBytes:          len(payload),
			InterpretedFirstContactCount:  countEvents(interpreted, "first_contact"),
			GeneratedFirstContactCount:    summary.FirstContactCount,
			InterpretedDataEvents:         countSemantic(interpreted, "data"),
			GeneratedDataEvents:           summary.DataEventCount,
			SemanticSimilarity:            report.SemanticSimilarity,
			StatePathSimilarity:           report.StatePathSimilarity,
			InterpretedMultiStreamEvents:  len(interpretedMulti),
			GeneratedMultiStreamEvents:    len(generatedMulti),
			GeneratedMultiStreamEchoBytes: multiSummary.EchoBytes,
			PayloadLogged:                 summary.PayloadLogged || traceContainsPayload(generated, payload),
		}
		run.SemanticEquivalent = run.GeneratedEchoBytes == len(payload) &&
			run.InterpretedFirstContactCount == run.GeneratedFirstContactCount &&
			run.InterpretedDataEvents > 0 &&
			run.GeneratedDataEvents > 0 &&
			!run.PayloadLogged
		run.MultiStreamEquivalent = interpretedMultiResult.OpenedStreams > 0 &&
			run.GeneratedMultiStreamEvents > 0 &&
			run.GeneratedMultiStreamEchoBytes > 0 &&
			!traceContainsPayload(generatedMulti, []byte("local lab multistream message"))
		corpus.ProfileRuns = append(corpus.ProfileRuns, run)
		corpus.InterpretedTraces = append(corpus.InterpretedTraces, interpreted)
		corpus.GeneratedTraces = append(corpus.GeneratedTraces, generated)
		corpus.InterpretedMultiStreamTraces = append(corpus.InterpretedMultiStreamTraces, interpretedMulti)
		corpus.GeneratedMultiStreamTraces = append(corpus.GeneratedMultiStreamTraces, generatedMulti)
		corpus.GeneratedDirs = append(corpus.GeneratedDirs, out)
		corpus.Profiles = append(corpus.Profiles, &GeneratedProfileRecord{ProfileID: p.ID, Seed: seed})
		profilesForScan = append(profilesForScan, out)
	}
	scan, err := codegen.ScanGeneratedOutputs(profilesForScan)
	if err != nil {
		return GeneratedBackendTraceCorpus{}, err
	}
	corpus.SourceScan = scan
	corpus.GeneratedModules = len(corpus.GeneratedDirs)
	return corpus, nil
}

func runGeneratedTraceCommand(ctx context.Context, dir string, payload []byte, multistream bool) ([]ktrace.Event, GeneratedTraceSummary, error) {
	tracePath := filepath.Join(dir, "generated-trace.jsonl")
	summaryPath := filepath.Join(dir, "generated-summary.json")
	args := []string{"run", "./cmd/generated-trace", "--trace", tracePath, "--summary", summaryPath}
	if multistream {
		args = append(args, "--multistream", "--streams", "4")
	} else {
		args = append(args, "--message", string(payload))
	}
	cmd := exec.CommandContext(ctx, goTool(), args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, GeneratedTraceSummary{}, fmt.Errorf("%w: %s", err, trimOutput(string(output)))
	}
	events, err := ktrace.ReadJSONL(tracePath)
	if err != nil {
		return nil, GeneratedTraceSummary{}, err
	}
	raw, err := os.ReadFile(summaryPath)
	if err != nil {
		return nil, GeneratedTraceSummary{}, err
	}
	var summary GeneratedTraceSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		return nil, GeneratedTraceSummary{}, err
	}
	return events, summary, nil
}

func GeneratedSemanticEquivalenceGate(corpus GeneratedBackendTraceCorpus) GateResult {
	failures := []string{}
	details := map[string]any{"profile_count": len(corpus.ProfileRuns)}
	for _, run := range corpus.ProfileRuns {
		if !run.SemanticEquivalent {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("generated_semantic_equivalence", len(failures) == 0, "required", fmt.Sprintf("%d generated/interpreted profile pairs checked; %d failures", len(corpus.ProfileRuns), len(failures)), details, failures)
}

func GeneratedProfileDiversityGate(corpus GeneratedBackendTraceCorpus) GateResult {
	total, separated := pairSeparation(corpus.GeneratedTraces)
	ratio := ratio(separated, total)
	if total == 0 {
		ratio = 1
	}
	failures := []string{}
	if total > 0 && ratio < 0.5 {
		failures = append(failures, "generated traces across profiles are insufficiently diverse")
	}
	return gate("generated_profile_diversity", len(failures) == 0, "required", fmt.Sprintf("%d/%d generated trace pairs separated", separated, total), map[string]any{
		"separated_pairs": separated,
		"total_pairs":     total,
		"ratio":           ratio,
		"min_ratio":       0.5,
	}, failures)
}

func GeneratedFixedSignatureGate(corpus GeneratedBackendTraceCorpus) GateResult {
	scan := ktrace.ScanTraces(corpus.GeneratedTraces, ktrace.DefaultStabilityThreshold)
	failures := []string{}
	details := map[string]any{"trace_count": scan.TraceCount}
	for _, metric := range scan.Metrics {
		details[metric.Name+"_stability"] = metric.Stability
		details[metric.Name+"_unique_values"] = metric.UniqueValues
		if metric.Total < 3 || !metric.Flagged {
			continue
		}
		if generatedSingleStreamMetricExplained(metric.Name) {
			continue
		}
		if metric.Name == "first_contact_message_count" && profileFirstContactCountsExplain(corpus) {
			continue
		}
		failures = append(failures, metric.Name+" too stable")
	}
	if !corpus.SourceScan.Passed {
		failures = append(failures, "source scanner found generated source artifacts")
	}
	return gate("generated_fixed_signature", len(failures) == 0, "required", fmt.Sprintf("%d trace stability metrics checked; %d failures", len(scan.Metrics), len(failures)), details, failures)
}

func generatedSingleStreamMetricExplained(name string) bool {
	switch name {
	case "stream_count", "stream_interleaving_pattern", "stream_priority_pattern", "window_update_pattern", "stream_close_reset_pattern", "backpressure_pattern":
		return true
	default:
		return false
	}
}

func GeneratedVsInterpretedDivergenceGate(corpus GeneratedBackendTraceCorpus) GateResult {
	summary := divergenceSummary(corpus)
	return gate("generated_vs_interpreted_divergence", true, "informational", summary.Assessment, map[string]any{
		"same_profile_semantic_similarity_average": summary.SameProfileSemanticSimilarityAverage,
		"same_profile_trace_similarity_average":    summary.SameProfileTraceSimilarityAverage,
		"generated_different_profile_diversity":    summary.GeneratedDifferentProfileDiversity,
		"interpreted_different_profile_diversity":  summary.InterpretedDifferentProfileDiversity,
		"assessment": summary.Assessment,
	}, nil)
}

func GeneratedMultiStreamParityGate(corpus GeneratedBackendTraceCorpus) GateResult {
	failures := []string{}
	for _, run := range corpus.ProfileRuns {
		if !run.MultiStreamEquivalent {
			failures = append(failures, run.ProfileID)
		}
	}
	total, separated := pairSeparation(corpus.GeneratedMultiStreamTraces)
	ratio := ratio(separated, total)
	if total > 0 && ratio < 0.5 {
		failures = append(failures, "generated multi-stream traces are insufficiently diverse")
	}
	return gate("multi_stream_generated_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated/interpreted multi-stream profile pairs checked", len(corpus.ProfileRuns)), map[string]any{
		"profile_count":               len(corpus.ProfileRuns),
		"generated_trace_count":       len(corpus.GeneratedMultiStreamTraces),
		"interpreted_trace_count":     len(corpus.InterpretedMultiStreamTraces),
		"separated_pairs":             separated,
		"total_pairs":                 total,
		"different_profile_ratio":     ratio,
		"min_different_profile_ratio": 0.5,
	}, failures)
}

func GeneratedStreamAdversaryParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module stream adversary tests failed")
	}
	missingMetadata := 0
	for _, events := range corpus.GeneratedMultiStreamTraces {
		if !traceHasStreamMetadata(events) {
			missingMetadata++
		}
	}
	if missingMetadata > 0 {
		failures = append(failures, "generated multi-stream traces missing safe stream metadata")
	}
	total, separated := pairSeparation(corpus.GeneratedMultiStreamTraces)
	ratio := ratio(separated, total)
	if total > 0 && ratio < 0.5 {
		failures = append(failures, "generated stream adversary traces are insufficiently diverse")
	}
	return gate("multi_stream_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules exercised stream adversary scenario tests", corpus.GeneratedModules), map[string]any{
		"generated_modules":        corpus.GeneratedModules,
		"generated_test_failures":  len(testFailures),
		"generated_trace_count":    len(corpus.GeneratedMultiStreamTraces),
		"missing_metadata_traces":  missingMetadata,
		"separated_pairs":          separated,
		"total_pairs":              total,
		"profile_diversity_ratio":  ratio,
		"scenario_tests_in_module": []string{"balanced_interleave", "bulk_vs_interactive", "reset_midstream", "blocked_stream"},
	}, failures)
}

func GeneratedProxySemParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module proxysem tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated proxysem specialization constants missing")
	}
	proxyFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/proxysem_generated.go" {
			proxyFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && proxyFiles < 2 {
		failures = append(failures, "generated proxysem specialized files did not differ")
	}
	return gate("proxy_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include proxysem tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"proxysem_unique_files":        proxyFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedCarrierParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module carrier tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated carrier specialization constants missing")
	}
	carrierFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/carrier_generated.go" {
			carrierFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && carrierFiles < 2 {
		failures = append(failures, "generated carrier specialized files did not differ")
	}
	return gate("carrier_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include carrier tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"carrier_unique_files":         carrierFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedSecurityParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module security tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated security specialization constants missing")
	}
	securityFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/security_generated.go" {
			securityFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && securityFiles < 2 {
		failures = append(failures, "generated security specialized files did not differ")
	}
	return gate("security_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include security tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"security_unique_files":        securityFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedRuntimeParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module runtime tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated runtime specialization constants missing")
	}
	runtimeFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/runtime_generated.go" {
			runtimeFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && runtimeFiles < 2 {
		failures = append(failures, "generated runtime specialized files did not differ")
	}
	return gate("runtime_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include runtime tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"runtime_unique_files":         runtimeFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedHardeningParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module hardening tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated hardening specialization constants missing")
	}
	hardeningFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/hardening_generated.go" {
			hardeningFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && hardeningFiles < 2 {
		failures = append(failures, "generated hardening specialized files did not differ")
	}
	return gate("hardening_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include hardening tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"hardening_unique_files":       hardeningFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module adapter tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated adapter specialization constants missing")
	}
	adapterFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/adapter_generated.go" {
			adapterFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && adapterFiles < 2 {
		failures = append(failures, "generated adapter specialized files did not differ")
	}
	return gate("adapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include adapter tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"adapter_unique_files":         adapterFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedLocalAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module local adapter tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated local adapter specialization constants missing")
	}
	localAdapterFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/localadapter_generated.go" {
			localAdapterFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && localAdapterFiles < 2 {
		failures = append(failures, "generated local adapter specialized files did not differ")
	}
	return gate("local_adapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include local adapter tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"local_adapter_unique_files":   localAdapterFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedProxyIngressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module proxyingress tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated proxyingress specialization constants missing")
	}
	proxyIngressFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/proxyingress_generated.go" {
			proxyIngressFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && proxyIngressFiles < 2 {
		failures = append(failures, "generated proxyingress specialized files did not differ")
	}
	return gate("proxyingress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include proxyingress tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"proxyingress_unique_files":    proxyIngressFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedLocalProxyIngressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module localproxyingress tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated localproxyingress specialization constants missing")
	}
	localProxyIngressFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/localproxyingress_generated.go" {
			localProxyIngressFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && localProxyIngressFiles < 2 {
		failures = append(failures, "generated localproxyingress specialized files did not differ")
	}
	return gate("localproxyingress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include localproxyingress tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":              corpus.GeneratedModules,
		"generated_test_failures":        len(testFailures),
		"localproxyingress_unique_files": localProxyIngressFiles,
		"generated_source_specialized":   corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedLocalProxyIngressAdvParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module localproxyingressadv tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated localproxyingressadv specialization constants missing")
	}
	localProxyIngressAdvFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/localproxyingressadv_generated.go" {
			localProxyIngressAdvFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && localProxyIngressAdvFiles < 2 {
		failures = append(failures, "generated localproxyingressadv specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"localproxyingressadv_generated.go", "localproxyingressadv_test.go", "localproxyingressadv_parity_test.go", "localproxyingressadv_hygiene_test.go", "LocalProxyIngressAdversarialSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated localproxyingressadv marker "+marker)
				}
			}
		}
	}
	return gate("localproxyingressadv_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include localproxyingressadv tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                 corpus.GeneratedModules,
		"generated_test_failures":           len(testFailures),
		"localproxyingressadv_unique_files": localProxyIngressAdvFiles,
		"generated_source_specialized":      corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedAdaptivePathParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module adaptivepath tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated adaptivepath specialization constants missing")
	}
	adaptivePathFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/adaptivepath_generated.go" {
			adaptivePathFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && adaptivePathFiles < 2 {
		failures = append(failures, "generated adaptivepath specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"adaptivepath_generated.go", "adaptivepath_test.go", "adaptivepath_parity_test.go", "adaptivepath_hygiene_test.go", "AdaptivePathSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated adaptivepath marker "+marker)
				}
			}
		}
	}
	return gate("adaptivepath_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include adaptivepath tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"adaptivepath_unique_files":    adaptivePathFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedTransportBundleParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module transportbundle tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated transportbundle specialization constants missing")
	}
	transportBundleFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/transportbundle_generated.go" {
			transportBundleFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && transportBundleFiles < 2 {
		failures = append(failures, "generated transportbundle specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"transportbundle_generated.go", "transportbundle_test.go", "transportbundle_parity_test.go", "transportbundle_hygiene_test.go", "TransportBundleSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated transportbundle marker "+marker)
				}
			}
		}
	}
	return gate("transportbundle_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include transportbundle tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                   corpus.GeneratedModules,
		"generated_test_failures":             len(testFailures),
		"transportbundle_unique_files":        transportBundleFiles,
		"generated_source_specialized":        corpus.SourceScan.ProfileSpecificConstantsPresent,
		"transportbundle_generated_artifacts": []string{"transportbundle_generated.go", "transportbundle_test.go", "transportbundle_parity_test.go", "transportbundle_hygiene_test.go"},
	}, failures)
}

func GeneratedPathRaceParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module pathrace tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated pathrace specialization constants missing")
	}
	pathRaceFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/pathrace_generated.go" {
			pathRaceFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && pathRaceFiles < 2 {
		failures = append(failures, "generated pathrace specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"pathrace_generated.go", "pathrace_test.go", "pathrace_parity_test.go", "pathrace_hygiene_test.go", "PathRaceSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated pathrace marker "+marker)
				}
			}
		}
	}
	return gate("pathrace_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include pathrace tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"pathrace_unique_files":        pathRaceFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
		"pathrace_generated_artifacts": []string{"pathrace_generated.go", "pathrace_test.go", "pathrace_parity_test.go", "pathrace_hygiene_test.go"},
	}, failures)
}

func GeneratedPathHealthParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module pathhealth tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated pathhealth specialization constants missing")
	}
	pathHealthFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/pathhealth_generated.go" {
			pathHealthFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && pathHealthFiles < 2 {
		failures = append(failures, "generated pathhealth specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"pathhealth_generated.go", "pathhealth_test.go", "pathhealth_parity_test.go", "pathhealth_hygiene_test.go", "PathHealthSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated pathhealth marker "+marker)
				}
			}
		}
	}
	return gate("pathhealth_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include pathhealth tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":              corpus.GeneratedModules,
		"generated_test_failures":        len(testFailures),
		"pathhealth_unique_files":        pathHealthFiles,
		"generated_source_specialized":   corpus.SourceScan.ProfileSpecificConstantsPresent,
		"pathhealth_generated_artifacts": []string{"pathhealth_generated.go", "pathhealth_test.go", "pathhealth_parity_test.go", "pathhealth_hygiene_test.go"},
	}, failures)
}

func GeneratedCarrierReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module carrierreview tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated carrierreview specialization constants missing")
	}
	carrierReviewFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/carrierreview_generated.go" {
			carrierReviewFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && carrierReviewFiles < 2 {
		failures = append(failures, "generated carrierreview specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"carrierreview_generated.go", "carrierreview_test.go", "carrierreview_parity_test.go", "carrierreview_hygiene_test.go", "CarrierReviewSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated carrierreview marker "+marker)
				}
			}
		}
	}
	return gate("carrierreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include carrierreview tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                 corpus.GeneratedModules,
		"generated_test_failures":           len(testFailures),
		"carrierreview_unique_files":        carrierReviewFiles,
		"generated_source_specialized":      corpus.SourceScan.ProfileSpecificConstantsPresent,
		"carrierreview_generated_artifacts": []string{"carrierreview_generated.go", "carrierreview_test.go", "carrierreview_parity_test.go", "carrierreview_hygiene_test.go"},
	}, failures)
}

func GeneratedMeasurementReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module measurementreview tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated measurementreview specialization constants missing")
	}
	measurementReviewFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/measurementreview_generated.go" {
			measurementReviewFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && measurementReviewFiles < 2 {
		failures = append(failures, "generated measurementreview specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"measurementreview_generated.go", "measurementreview_test.go", "measurementreview_parity_test.go", "measurementreview_hygiene_test.go", "MeasurementReviewSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated measurementreview marker "+marker)
				}
			}
		}
	}
	return gate("measurementreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include measurementreview tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                     corpus.GeneratedModules,
		"generated_test_failures":               len(testFailures),
		"measurementreview_unique_files":        measurementReviewFiles,
		"generated_source_specialized":          corpus.SourceScan.ProfileSpecificConstantsPresent,
		"measurementreview_generated_artifacts": []string{"measurementreview_generated.go", "measurementreview_test.go", "measurementreview_parity_test.go", "measurementreview_hygiene_test.go"},
	}, failures)
}

func GeneratedProxyEgressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "proxyegress", "proxy egress", "ProxyEgressSchemaVersion")
}

func GeneratedRelayBridgeParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "relaybridge", "relay bridge", "RelayBridgeSchemaVersion")
}

func GeneratedLocalPipelineParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localpipeline", "local pipeline", "LocalPipelineSchemaVersion")
}

func GeneratedProductionReadinessParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "productionreadiness", "production readiness", "ProductionReadinessSchemaVersion")
}

func GeneratedConcreteLocalAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "concretelocaladapter", "concrete local adapter", "ConcreteLocalAdapterSchemaVersion")
}

func GeneratedLocalProtocolAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localprotocoladapter", "local protocol adapter", "LocalProtocolAdapterSchemaVersion")
}

func GeneratedLoopbackRelayParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "loopbackrelay", "loopback relay", "LoopbackRelaySchemaVersion")
}

func GeneratedLabEgressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "labegress", "lab egress", "LabEgressSchemaVersion")
}

func GeneratedCarrierReadinessParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "carrierreadiness", "carrier readiness", "CarrierReadinessSchemaVersion")
}

func GeneratedHTTPSCarrierReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "httpscarrierreview", "HTTPS carrier review", "HTTPSCarrierReviewSchemaVersion")
}

func GeneratedHTTPSLikeCarrierParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "httpslikecarrier", "HTTPS-like carrier", "HTTPSLikeCarrierSchemaVersion")
}

func GeneratedHTTPSCarrierAdversaryParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "httpscarrieradversary", "HTTPS carrier adversary", "HTTPSCarrierAdversarySchemaVersion")
}

func GeneratedConstrainedCarrierReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "constrainedcarrierreview", "constrained carrier review", "ConstrainedCarrierReviewSchemaVersion")
}

func GeneratedConstrainedCarrierParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "constrainedcarrier", "constrained carrier", "ConstrainedCarrierSchemaVersion")
}

func GeneratedMultiCarrierSelectParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "multicarrierselect", "multi-carrier selection", "MultiCarrierSelectSchemaVersion")
}

func GeneratedCarrierCollapseParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "carriercollapse", "carrier collapse", "CarrierCollapseSchemaVersion")
}

func GeneratedLocalProxyAdapterReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localproxyadapterreview", "local proxy adapter review", "LocalProxyAdapterReviewSchemaVersion")
}

func GeneratedLocalProxyAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localproxyadapter", "local proxy adapter", "LocalProxyAdapterSchemaVersion")
}

func GeneratedVPNSemanticsParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "vpnsemantics", "VPN semantics", "PacketSemanticsSchemaVersion")
}

func GeneratedLocalVPNAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localvpnadapter", "local packet adapter", "PacketAdapterSchemaVersion")
}

func GeneratedRelayProcessParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "relayprocess", "relay process architecture", "RelayProcessSchemaVersion")
}

func GeneratedKeyExchangePlanParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "keyexchangeplan", "production key exchange design", "KeyExchangePlanSchemaVersion")
}

func GeneratedRelayAuthPlanParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "relayauthplan", "relay auth rotation compatibility", "RelayAuthPlanSchemaVersion")
}

func GeneratedOperationalHardeningParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "operationalhardening", "relay/runtime operational hardening", "OperationalHardeningSchemaVersion")
}

func GeneratedAndroidReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "androidreview", "Android architecture review", "AndroidReviewSchemaVersion")
}

func GeneratedAndroidRuntimeParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "androidruntime", "Android local runtime port", "AndroidRuntimeSchemaVersion")
}

func GeneratedAndroidVPNServiceParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "androidvpnservice", "Android VpnService prototype", "AndroidVpnServiceSchemaVersion")
}

func GeneratedAndroidCarrierParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "androidcarrier", "Android carrier integration", "AndroidCarrierSchemaVersion")
}

func generatedMilestoneSourceGate(corpus GeneratedBackendTraceCorpus, testFailures []string, slug, label, schemaMarker string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module "+label+" tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated "+label+" specialization constants missing")
	}
	uniqueFiles := 0
	generatedRel := "protocol/" + slug + "_generated.go"
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == generatedRel {
			uniqueFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && uniqueFiles < 2 {
		failures = append(failures, "generated "+label+" specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{slug + "_generated.go", slug + "_test.go", slug + "_parity_test.go", slug + "_hygiene_test.go", schemaMarker} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated "+slug+" marker "+marker)
				}
			}
		}
	}
	return gate(slug+"_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include %s tests and constants", corpus.GeneratedModules, label), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		slug + "_unique_files":         uniqueFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
		slug + "_generated_artifacts":  []string{slug + "_generated.go", slug + "_test.go", slug + "_parity_test.go", slug + "_hygiene_test.go"},
	}, failures)
}

func GeneratedByteTransportParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module byte transport tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated byte transport specialization constants missing")
	}
	byteTransportFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/bytetransport_generated.go" {
			byteTransportFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && byteTransportFiles < 2 {
		failures = append(failures, "generated byte transport specialized files did not differ")
	}
	return gate("byte_transport_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include byte transport tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"byte_transport_unique_files":  byteTransportFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedBytePathFixtureParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module bytepath fixture tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated bytepath fixture specialization constants missing")
	}
	root, err := repoRoot()
	if err != nil {
		failures = append(failures, err.Error())
	} else {
		raw, readErr := codegenGeneratorSource(root)
		if readErr != nil {
			failures = append(failures, readErr.Error())
		} else {
			text := string(raw)
			for _, marker := range []string{"bytepath_fixture_test.go", "bytepath_parity_test.go", "BytePathFixtureSchemaVersion", "byteparity.Run"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated bytepath marker "+marker)
				}
			}
		}
	}
	return gate("bytepath_fixture_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include bytepath fixture/parity tests", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedSourceScannerGate(scan codegen.SourceScanReport) GateResult {
	return gate("generated_source_scanner", scan.Passed, "required", fmt.Sprintf("%d generated modules scanned; %d failures", scan.GeneratedModules, len(scan.Failures)), map[string]any{
		"profile_specific_constants_present": scan.ProfileSpecificConstantsPresent,
		"specialized_files_differ":           scan.SpecializedFilesDiffer,
		"direct_fsm_use":                     scan.DirectFSMUse,
		"runtime_profile_load":               scan.RuntimeProfileLoad,
		"payload_logging":                    scan.PayloadLogging,
		"wrapper_only":                       scan.WrapperOnly,
	}, scan.Failures)
}

func GeneratedMutantDetectionGate(ctx context.Context, modes []string, count int) GateResult {
	if count <= 0 {
		count = 4
	}
	thresholds := DefaultThresholds()
	thresholds.MinFirstContactPatterns = 2
	thresholds.MinFrameGrammarCombinations = 2
	thresholds.MinSchedulerCombinations = 2
	thresholds.MinPaddingCombinations = 2
	thresholds.MinInvalidInputCombinations = 2
	thresholds.MinDifferentTraceSeparationRatio = 0.5
	detected := []string{}
	missed := []string{}
	modeDetails := map[string]any{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 700, count)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		traces := mutant.TraceFixtures(mode, profiles)
		summary := diversity.SummarizeCorpus(700, profiles)
		scan := ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold)
		gates := []GateResult{
			ProfileCorpusDiversityGate(summary, thresholds),
			BlackBoxTraceDiversityGate(scan, thresholds),
			FixedSignatureGate(profiles, traces, thresholds),
			DifferentProfileSeparationGate(traces, thresholds),
		}
		failed := []string{}
		for _, gate := range gates {
			if !gate.Passed {
				failed = append(failed, gate.Name)
			}
		}
		modeDetails[mode] = failed
		if len(failed) == 0 {
			missed = append(missed, mode)
		} else {
			detected = append(detected, mode)
		}
	}
	return gate("generated_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d mutant modes detected", len(detected), len(modes)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
		"mode_failures":  modeDetails,
		"fixture_based":  true,
	}, missed)
}

func buildCodegenSummary(corpus GeneratedBackendTraceCorpus, gates []GateResult) CodegenAuditSummary {
	status := func(name string) string {
		if gate, ok := gateByName(gates, name); ok {
			if gate.Passed {
				return "passed"
			}
			return "failed"
		}
		return "missing"
	}
	return CodegenAuditSummary{
		Profiles:                         corpus.ProfileCount,
		GeneratedModules:                 corpus.GeneratedModules,
		SemanticEquivalence:              status("generated_semantic_equivalence"),
		GeneratedProfileDiversity:        status("generated_profile_diversity"),
		FixedSignature:                   status("generated_fixed_signature"),
		MutantDetection:                  status("generated_mutant_detection"),
		MultiStreamGeneratedParity:       status("multi_stream_generated_parity"),
		StreamAdversaryParity:            status("multi_stream_generated_backend_parity"),
		ProxySemGeneratedParity:          status("proxy_generated_backend_parity"),
		CarrierGeneratedParity:           status("carrier_generated_backend_parity"),
		SecurityGeneratedParity:          status("security_generated_backend_parity"),
		RuntimeGeneratedParity:           status("runtime_generated_backend_parity"),
		HardeningGeneratedParity:         status("hardening_generated_backend_parity"),
		AdapterGeneratedParity:           status("adapter_generated_backend_parity"),
		LocalAdapterGeneratedParity:      status("local_adapter_generated_backend_parity"),
		ByteTransportGeneratedParity:     status("byte_transport_generated_backend_parity"),
		BytePathFixtureParity:            status("bytepath_fixture_generated_backend_parity"),
		WireFeaturesGeneratedParity:      status("wirefeatures_generated_backend_parity"),
		WireGenGeneratedParity:           status("wiregen_generated_backend_parity"),
		HostDetectGeneratedParity:        status("hostdetect_generated_backend_parity"),
		RelayFleetGeneratedParity:        status("relayfleet_generated_backend_parity"),
		ProxyIngressGeneratedParity:      status("proxyingress_generated_backend_parity"),
		LocalProxyIngressGeneratedParity: status("localproxyingress_generated_backend_parity"),
		LocalProxyIngressAdvParity:       status("localproxyingressadv_generated_backend_parity"),
		AdaptivePathGeneratedParity:      status("adaptivepath_generated_backend_parity"),
		TransportBundleGeneratedParity:   status("transportbundle_generated_backend_parity"),
		PathRaceGeneratedParity:          status("pathrace_generated_backend_parity"),
		PathHealthGeneratedParity:        status("pathhealth_generated_backend_parity"),
		CarrierReviewGeneratedParity:     status("carrierreview_generated_backend_parity"),
		MeasurementReviewGeneratedParity: status("measurementreview_generated_backend_parity"),
		ProxyEgressGeneratedParity:       status("proxyegress_generated_backend_parity"),
		RelayBridgeGeneratedParity:       status("relaybridge_generated_backend_parity"),
		LocalPipelineGeneratedParity:     status("localpipeline_generated_backend_parity"),
		ProductionReadinessParity:        status("productionreadiness_generated_backend_parity"),
		ConcreteLocalAdapterParity:       status("concretelocaladapter_generated_backend_parity"),
		LocalProtocolAdapterParity:       status("localprotocoladapter_generated_backend_parity"),
		LoopbackRelayParity:              status("loopbackrelay_generated_backend_parity"),
		LabEgressParity:                  status("labegress_generated_backend_parity"),
		CarrierReadinessParity:           status("carrierreadiness_generated_backend_parity"),
		HTTPSCarrierReviewParity:         status("httpscarrierreview_generated_backend_parity"),
		HTTPSLikeCarrierParity:           status("httpslikecarrier_generated_backend_parity"),
		HTTPSCarrierAdversaryParity:      status("httpscarrieradversary_generated_backend_parity"),
		ConstrainedCarrierReviewParity:   status("constrainedcarrierreview_generated_backend_parity"),
		ConstrainedCarrierParity:         status("constrainedcarrier_generated_backend_parity"),
		MultiCarrierSelectParity:         status("multicarrierselect_generated_backend_parity"),
		CarrierCollapseParity:            status("carriercollapse_generated_backend_parity"),
		LocalProxyAdapterReviewParity:    status("localproxyadapterreview_generated_backend_parity"),
		LocalProxyAdapterParity:          status("localproxyadapter_generated_backend_parity"),
		VPNSemanticsParity:               status("vpnsemantics_generated_backend_parity"),
		LocalVPNAdapterParity:            status("localvpnadapter_generated_backend_parity"),
		RelayProcessParity:               status("relayprocess_generated_backend_parity"),
		KeyExchangePlanParity:            status("keyexchangeplan_generated_backend_parity"),
		RelayAuthPlanParity:              status("relayauthplan_generated_backend_parity"),
		OperationalHardeningParity:       status("operationalhardening_generated_backend_parity"),
		AndroidReviewParity:              status("androidreview_generated_backend_parity"),
		AndroidRuntimeParity:             status("androidruntime_generated_backend_parity"),
		AndroidVPNServiceParity:          status("androidvpnservice_generated_backend_parity"),
		AndroidCarrierParity:             status("androidcarrier_generated_backend_parity"),
		SourceScanner:                    status("generated_source_scanner"),
		InterpretedVsGenerated:           divergenceSummary(corpus),
		SourceScan:                       corpus.SourceScan,
		LegacyEvidenceClass:              "legacy_non_evidentiary_parity",
	}
}

func divergenceSummary(corpus GeneratedBackendTraceCorpus) InterpretedGeneratedDivergence {
	var semanticTotal, traceTotal float64
	for _, run := range corpus.ProfileRuns {
		semanticTotal += run.SemanticSimilarity
		traceTotal += (run.SemanticSimilarity + run.StatePathSimilarity) / 2
	}
	sameSemantic := ratioFloat(semanticTotal, len(corpus.ProfileRuns))
	sameTrace := ratioFloat(traceTotal, len(corpus.ProfileRuns))
	generatedTotal, generatedSeparated := pairSeparation(corpus.GeneratedTraces)
	interpretedTotal, interpretedSeparated := pairSeparation(corpus.InterpretedTraces)
	generatedDiversity := ratio(generatedSeparated, generatedTotal)
	interpretedDiversity := ratio(interpretedSeparated, interpretedTotal)
	assessment := "equally diverse"
	if generatedDiversity > interpretedDiversity+0.05 {
		assessment = "generated appears more diverse"
	}
	if generatedDiversity+0.05 < interpretedDiversity {
		assessment = "generated appears less diverse"
	}
	return InterpretedGeneratedDivergence{
		SameProfileSemanticSimilarityAverage: sameSemantic,
		SameProfileTraceSimilarityAverage:    sameTrace,
		GeneratedDifferentProfileDiversity:   generatedDiversity,
		InterpretedDifferentProfileDiversity: interpretedDiversity,
		Assessment:                           assessment,
	}
}

func profileFirstContactCountsExplain(corpus GeneratedBackendTraceCorpus) bool {
	if len(corpus.ProfileRuns) == 0 {
		return true
	}
	for _, run := range corpus.ProfileRuns {
		if run.InterpretedFirstContactCount != run.GeneratedFirstContactCount {
			return false
		}
	}
	return true
}

func pairSeparation(traces [][]ktrace.Event) (int, int) {
	total, separated := 0, 0
	for i := 0; i < len(traces); i++ {
		for j := i + 1; j < len(traces); j++ {
			total++
			if ktrace.CompareEvents(traces[i], traces[j]).MeaningfullyDifferent {
				separated++
				continue
			}
			a := adversary.ExtractFeaturesWithMetadata(fmt.Sprintf("a_%d", i), "", traces[i])
			b := adversary.ExtractFeaturesWithMetadata(fmt.Sprintf("b_%d", j), "", traces[j])
			if adversary.Distance(a, b) >= DefaultThresholds().MinDifferentProfileDistance {
				separated++
			}
		}
	}
	return total, separated
}

func countEvents(events []ktrace.Event, eventType string) int {
	count := 0
	for _, ev := range events {
		if ev.EventType == eventType {
			count++
		}
	}
	return count
}

func countSemantic(events []ktrace.Event, semantic string) int {
	count := 0
	for _, ev := range events {
		if ev.Semantic == semantic {
			count++
		}
	}
	return count
}

func traceContainsPayload(events []ktrace.Event, payload []byte) bool {
	raw, _ := json.Marshal(events)
	return len(payload) > 0 && strings.Contains(string(raw), string(payload))
}

func codegenAuditPayload() []byte {
	return []byte("hello generated")
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}

func ratioFloat(numerator float64, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return numerator / float64(denominator)
}

func runGoTest(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, goTool(), "test", "./...")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func goTool() string {
	if p := os.Getenv("GO"); p != "" {
		return p
	}
	if goroot := runtime.GOROOT(); goroot != "" {
		name := "go"
		if runtime.GOOS == "windows" {
			name = "go.exe"
		}
		candidate := filepath.Join(goroot, "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "go"
}

func uniqueStrings(values []string) int {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	return len(seen)
}

func trimOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 2000 {
		return value
	}
	return value[:2000] + "\n..."
}
