// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCIThirdPartyActionsAreExactSHAPins(t *testing.T) {
	data := readRepositoryFile(t, ".github", "workflows", "ci.yml")
	matches := regexp.MustCompile(`(?m)^\s*uses:\s*([^@\s]+)@([0-9a-f]+)(?:\s*#.*)?$`).FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatal("no CI action references found")
	}
	expected := map[string]string{
		"actions/checkout":   "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"actions/setup-go":   "4a3601121dd01d1626a1e23e37211e3254c1c06c",
		"actions/setup-java": "f2beeb24e141e01a676f977032f5a29d81c9e27e",
	}
	for _, match := range matches {
		if len(match[2]) != 40 {
			t.Errorf("%s is not pinned to a full commit SHA", match[1])
			continue
		}
		want, ok := expected[match[1]]
		if !ok {
			t.Errorf("unreviewed CI action %s", match[1])
			continue
		}
		if match[2] != want {
			t.Errorf("%s pin=%s, want %s", match[1], match[2], want)
		}
	}
}

func TestGradleWrapperAndDependencyVerificationArePinned(t *testing.T) {
	properties := string(readRepositoryFile(t, "android", "gradle", "wrapper", "gradle-wrapper.properties"))
	for _, required := range []string{
		"distributionUrl=https\\://services.gradle.org/distributions/gradle-9.4.1-bin.zip",
		"distributionSha256Sum=2ab2958f2a1e51120c326cad6f385153bb11ee93b3c216c5fccebfdfbb7ec6cb",
		"validateDistributionUrl=true",
	} {
		if !strings.Contains(properties, required) {
			t.Errorf("Gradle wrapper is missing %q", required)
		}
	}
	jar := readRepositoryFile(t, "android", "gradle", "wrapper", "gradle-wrapper.jar")
	sum := sha256.Sum256(jar)
	if got, want := hex.EncodeToString(sum[:]), "55243ef57851f12b070ad14f7f5bb8302daceeebc5bce5ece5fa6edb23e1145c"; got != want {
		t.Errorf("Gradle wrapper JAR sha256=%s, want %s", got, want)
	}
	verification := string(readRepositoryFile(t, "android", "gradle", "verification-metadata.xml"))
	if !strings.Contains(verification, "<verify-metadata>true</verify-metadata>") ||
		!strings.Contains(verification, "<sha256 value=") {
		t.Fatal("Gradle dependency verification metadata is not checksum-enforcing")
	}
	if strings.Contains(verification, "<trusted-artifacts>") {
		t.Fatal("Gradle dependency verification must not broadly trust IDE source artifacts")
	}
	sourceArtifactCount := strings.Count(verification, `-sources.jar">`)
	if sourceArtifactCount < 378 {
		t.Fatalf("Gradle dependency verification has %d exact source-artifact entries, want at least 378", sourceArtifactCount)
	}
	reviewedAttachmentOrigins := strings.Count(verification, `origin="Android Studio source artifact; Gradle cache content address verified"`) +
		strings.Count(verification, `origin="Google Maven HTTPS bytes independently matched to Gradle cache"`) +
		strings.Count(verification, `origin="Maven Central HTTPS bytes independently matched to Gradle cache"`)
	const reviewedJavadocArtifacts = 24
	if reviewedAttachmentOrigins != sourceArtifactCount+reviewedJavadocArtifacts {
		t.Fatalf("Gradle dependency verification has %d reviewed attachment origins for %d exact source and Javadoc artifacts", reviewedAttachmentOrigins, sourceArtifactCount+reviewedJavadocArtifacts)
	}
	ideAttachmentArtifacts := map[string]string{
		"junit-4.13.2-sources.jar":                             "34181df6482d40ea4c046b063cb53c7ffae94bdf1b1d62695bdf3adf9dea7e3a",
		"hamcrest-core-1.3-sources.jar":                        "e223d2d8fbafd66057a8848cc94222d63c3cedd652cc48eddc0ab5c39c0f84df",
		"annotation-experimental-1.4.1-sources.jar":            "783a221a7c1093ff8932053998a69a24489f7930806a32b55366108146d29c1d",
		"annotation-jvm-1.9.1-sources.jar":                     "c6ae897fbfb73ca09d4ae31a24bfff85c652097ad10644cdbb738488728cb39b",
		"core-common-2.2.0-sources.jar":                        "563d430880d847890029234386ef03adb95403c34f3c9dec3a7002e2f4007ae4",
		"core-runtime-2.2.0-sources.jar":                       "4adaab3a8ab711634d566d2e239e199af8b5ac92c1de85540dc34c7040754e96",
		"camera-camera2-1.6.1-sources.jar":                     "9a43968bb27ff7a6960932b5dffc190930567d8bb52fff59541d372f7331b803",
		"camera-core-1.6.1-samples-sources.jar":                "d70c01d96bbe4abbb691312514f6708f9ba866f38003d698db31eda2a529a9c9",
		"camera-core-1.6.1-sources.jar":                        "864e7da58824da3146100100da588dfcb8f69c7a82369502a7873e9c941ae10c",
		"camera-lifecycle-1.6.1-samples-sources.jar":           "9d5a66f7a9d44f86dcca624a1a7284edba6dabe1da2ab3d681797523fa35568c",
		"camera-lifecycle-1.6.1-sources.jar":                   "573cdf43f2584f154b83788ab9683affd6124a61b78f6f7a17339c5e8d8d845c",
		"camera-video-1.6.1-samples-sources.jar":               "87976820a73a4d6640879bc475654f9a23820d5a329efb096429cbb71d104315",
		"camera-video-1.6.1-sources.jar":                       "dc8f8ac4f891fdaa76087ab43ce79b9a8386f507c5cf351d7189eabde1074a66",
		"camera-view-1.6.1-sources.jar":                        "dfb710c6d7b08e339a46807f08b609a92aff7988929f91b8f3427a44e5554e31",
		"collection-jvm-1.5.0-sources.jar":                     "bcc6197ec5fb349e86ae3ba6c94b164d3a9ac5a03d9f9c235d7c4eb24e5878b3",
		"animation-1.8.1-samples-sources.jar":                  "43c34f29475a01ffdad25f3c0bfdd130f1dee8d5718992263562dfd130ef772c",
		"animation-android-1.8.1-sources.jar":                  "b579efb1b1e818cb02c77a18971a758bf41e1ed757c5ee68bc45108d4dbbfa06",
		"animation-core-1.8.1-samples-sources.jar":             "78a774beb3943ae731753d64622dc3a9d2325950a29079b5f9bd3489ab17bffa",
		"animation-core-android-1.8.1-sources.jar":             "031c73801b3825e7a52fceadde3fc539ab95a95473d3bd70984af51772a22134",
		"foundation-1.8.1-samples-sources.jar":                 "72d923f928702f5397ec35d0a1f60d781af07d396bb8f3d3d98d297f4e044ece",
		"foundation-android-1.8.1-sources.jar":                 "837c651512f7b6f518e958e772d07ef6c001b236505f7e1ac266b842a8236cf7",
		"foundation-layout-1.8.1-samples-sources.jar":          "6d2900469064221e0439645ad719a5eca5a28300f9ca5052dd1cc0bd9cb14e97",
		"foundation-layout-android-1.8.1-sources.jar":          "f5b56c09ffd861171f0d092998389e6ae7c863764e52cc09d8dc8127890a0bab",
		"material-ripple-android-1.8.1-sources.jar":            "d2d0168acf371a8a036fb8ed6a41cb95ad5d6efd81818423dec488edacbf4585",
		"material3-1.4.0-samples-sources.jar":                  "699d0ca959a2705434836bfac343d20cdb2973e9dc23656fa9c0993a8b54909b",
		"material3-android-1.4.0-sources.jar":                  "3e3209422a382566a780e2c1410edd866e4474498098fdbcf942c690ade1ddaa",
		"runtime-1.11.4-samples-sources.jar":                   "e18ea05c4bebbdca433f3578e9e88501222a110883cbc5d5cbb5c7b0e084d7c7",
		"runtime-android-1.11.4-sources.jar":                   "211c6dc3f74166fbb5438264408e59b80c55544f201e04625f27d2cbd2dc462a",
		"runtime-annotation-1.11.4-samples-sources.jar":        "728e5ed27524324dc79b771f67891f711058041ef3d6b805edbe0e4c0fea3fd4",
		"runtime-annotation-android-1.11.4-sources.jar":        "faddbe6240e43542fcccfb4106f15b36494facbd81dc18e58124c1327dfe4fb1",
		"runtime-retain-1.11.4-samples-sources.jar":            "1b76c3cdfc41207bc6f36c7b1a5f60e6917b09fc3bf5f68a090ae878cf2370b7",
		"runtime-retain-android-1.11.4-sources.jar":            "6dab377d2582f7a2b7fcea90dda660ef49f6560081b899bb81e0b597cfa01dfc",
		"runtime-saveable-1.11.4-samples-sources.jar":          "d0bd72443e52be73b831a94052e2a1fa733d6dfbbfa9ff57c67075b75c02de0d",
		"runtime-saveable-android-1.11.4-sources.jar":          "305dfb9a5cdad3c53ba6297db6f96ca9c0d9f1856f83874ee12cc7fb7d028699",
		"ui-1.11.4-samples-sources.jar":                        "2dbebb539bae1a0448e0a813d741cc05da4b9820531d029f77599f080475935c",
		"ui-android-1.11.4-sources.jar":                        "aafb071a46db33fc841234f58061c5bc543ddaa2c8e56247409cee8e81a7b6d2",
		"ui-geometry-android-1.11.4-sources.jar":               "8b4ab7f4776d1e1d78fbdde46637bfe51f01e365d13d5253b905bf3f0361b0e0",
		"ui-graphics-1.11.4-samples-sources.jar":               "1065b28a74543f305ddbd5c7018c719d894dd60c974b14f8ef76702af72f3343",
		"ui-graphics-android-1.11.4-sources.jar":               "4bea68c9e9b51dcdd99c6ff19d07b202715393985b61548cc7b31e33065e8823",
		"ui-text-1.11.4-samples-sources.jar":                   "2540d3b6b926b0dc2047e93c62b30b954ab865d3f58870463925141323b3c85b",
		"ui-text-android-1.11.4-sources.jar":                   "550fad8823a16fbfc4ef251b2b85f9d335e73a44230478fbf9a52391d7b82131",
		"ui-unit-1.11.4-samples-sources.jar":                   "fdcf3d785b1f0fad25368f9152c1c1e03c02071ee3e9155f998752f1abfa2300",
		"ui-unit-android-1.11.4-sources.jar":                   "c6e2ea6314bfc45e27c5f28fda333afe2ed76748a004eec95f86cbdab099a6ff",
		"ui-util-android-1.11.4-sources.jar":                   "78ecea99219f527b216dc744c4188735fdf5755055d0313f6ea78dcb8f060390",
		"core-ktx-1.17.0-sources.jar":                          "360e212c1d7926d5eaebcea1eed68e2eff73dabb2ed9f34b4dfcc6e46ce0c0d1",
		"core-viewtree-1.0.0-sources.jar":                      "7026f2086f667720c43d4ca6bc58ab016d122ae0a404ca94e5fef6a7090e0984",
		"core-1.17.0-samples-sources.jar":                      "a487797562cc32e1233334574ca1681d36063ec9a4399c44e9d007a633dcd3a3",
		"core-1.17.0-sources.jar":                              "842c59707cbc1de9afbaa3dd5918f3317746f3c921e18c62193678f3efec5c83",
		"lifecycle-common-jvm-2.10.0-sources.jar":              "7f3dd285e49950c7b4e8b493ce397ba08d672455577143509d5218f314b3dc62",
		"lifecycle-livedata-core-ktx-2.10.0-sources.jar":       "20e0447343b348bc66275a8601ee4fc95bd83624620155e6ac7b2f80fe0aeafd",
		"lifecycle-livedata-core-2.10.0-sources.jar":           "2a7e7f5ac6c3716d214cbeb2b6459c3d9de74e4fa169f99c198210626c701cba",
		"lifecycle-livedata-2.10.0-sources.jar":                "17b5c634db9da69c4d0d50d4d23ec83961a119aa5eb8ae7fce2d75ca9bbd2e89",
		"lifecycle-runtime-android-2.10.0-sources.jar":         "d231316b84e92d179c4fc2bce85b560fe00f32b36bd4b5bde901a6ded60ca7b5",
		"lifecycle-runtime-compose-2.10.0-samples-sources.jar": "a704d9a7753899d7fa191e6403cc2bd99e45312a6222794382cddaae81730471",
		"lifecycle-runtime-compose-android-2.10.0-sources.jar": "37d2116e5b1c76292cf2406293d5e5210c6cf100be0020c0034a4f58e7e881dd",
		"lifecycle-runtime-ktx-android-2.10.0-sources.jar":     "c5df5b7bfa9c6d61ef14047bd9de207db688188c0d5d7b5f5c4ad6613806b1fc",
		"savedstate-1.3.2-samples-sources.jar":                 "53346ce0ace2e73c49030da45c03357ed857ec819d82f6da43ba8a22539b39e6",
		"savedstate-android-1.3.2-sources.jar":                 "6749d720e67c3bcfef3380ba4b98ccafb6a9a57d9298d8abaa17242351a53224",
		"savedstate-compose-1.3.2-samples-sources.jar":         "87632984d47b10696a5b49c80c6876e0e1e65713695807959e10496b8912ba45",
		"savedstate-compose-android-1.3.2-sources.jar":         "e5e73c5468cb23da524156e64051417342e21c9bcfdefc1ae3a939a54c7ad5f5",
		"versionedparcelable-1.1.1-sources.jar":                "135016af471acf4cd9583d36ceb779710c6b46812ccaaef7c526d5d60eae6b0b",
		"error_prone_annotations-2.18.0-sources.jar":           "a2c0783981c8ad48faaa6ea8de6f1926d8e87c125f5df5ce531a9810b943e032",
		"failureaccess-1.0.1-sources.jar":                      "092346eebbb1657b51aa7485a246bf602bb464cc0b0e2e1c7e7201fadce1e98f",
		"guava-32.0.1-android-sources.jar":                     "021d9cf4db17b3132949a48dd90c783cca49599863ebae649d5ba4a0a8662954",
		"j2objc-annotations-2.8-sources.jar":                   "7413eed41f111453a08837f5ac680edded7faed466cbd35745e402e13f4cc3f5",
		"core-3.5.4-sources.jar":                               "a611e3b63b661aeb2a81b8b4f4bde2daace1e2976adbb37917a674a0019c8fac",
		"checker-qual-3.33.0-sources.jar":                      "443fa6151982bb4c6ce62e2938f53660085b13a7dceb517202777b87d0dea2c7",
		"annotations-23.0.0-sources.jar":                       "ff2309b42f7584520497bb48bc609aca04c9886cf48708f14be83f00423ec144",
		"kotlin-stdlib-2.3.10-sources.jar":                     "21a3acec677a5483cacd6e956bee49f1f816c0e9ece3b39d188b6fd3720fd306",
		"kotlinx-coroutines-android-1.10.2-sources.jar":        "e903e0f46b8c5337816f2492ac3f9f543cb21ebf6b80fd0dbfe8cf38d1f3ebcf",
		"kotlinx-coroutines-core-jvm-1.10.2-sources.jar":       "cd86e9635cc7ac1b7d9854ed589e3041fb11cc67d2273e7d312278ba5628e2c8",
		"kotlinx-serialization-core-jvm-1.7.3-sources.jar":     "d084ce9bf130919d4b899db09896531440d1e330919187c7932d7fe0fa5257b8",
	}
	for artifact, checksum := range ideAttachmentArtifacts {
		pattern := regexp.MustCompile(
			`<artifact name="` + regexp.QuoteMeta(artifact) + `">\s*` +
				`<sha256 value="` + checksum + `" origin="(?:Google Maven|Maven Central) HTTPS bytes independently matched to Gradle cache"/>\s*` +
				`</artifact>`,
		)
		if !pattern.MatchString(verification) {
			t.Errorf("Gradle dependency verification is missing reviewed IDE attachment %s", artifact)
		}
	}
	javadocArtifacts := map[string]string{
		"junit-1.1.5-javadoc.jar":                    "055ab12367c23ef8897a1e771a6872fcf5d0324b59f77a1aff2cab880a0aaf22",
		"error_prone_annotations-2.30.0-javadoc.jar": "50d06c4aaa5ff276148985285b057b205c42df25bae67fc3ec958c3553724632",
		"hamcrest-library-1.3-javadoc.jar":           "1f72eb23230afdd4951758c623c8eefc742f4e79daf2318802425863fbf2886c",
		"listenablefuture-1.0-javadoc.jar":           "21830fbbd412cc2876c990a816e78280c8f85359494a3373b44bce58d2a05b02",
		"annotations-13.0-javadoc.jar":               "189d6d7726b293869ae97bc35bdab234f46e735549516974260543ce26df1d47",
		"junit-4.13.2-javadoc.jar":                   "9607be074b0200ce78f544a52ecae544b1ba559f430ba5b6c4ff110e30db0b8c",
		"hamcrest-core-1.3-javadoc.jar":              "27f7327aee87324952da2405b02094df40a4e772b48dae7e419d8b50067ca745",
		"auto-value-annotations-1.6.3-javadoc.jar":   "b4ac9ec0b90eaec5834c37d42dca17e7013c3ae9f49b604ba808e04311f96baa",
		"dagger-2.59-javadoc.jar":                    "38b8b343dbf86fdf2538c2c36999612f585517d4ed26a86534f975e139435260",
		"error_prone_annotations-2.28.0-javadoc.jar": "e2012d371e639537de463d40a823667ada149b2190ead528862a75008f339ecb",
		"failureaccess-1.0.2-javadoc.jar":            "40624507b9b91057a6e32186068c06ceada19c0266b42bac876d9b458a372aa7",
		"j2objc-annotations-3.0.0-javadoc.jar":       "31ba95273e92cffb2102ca7d80dabdec1ebea6f22e1370e259e4f259443c339b",
		"jakarta.inject-api-2.0.1-javadoc.jar":       "846348f27e60e4aa1d12b200a3b07d7a026ae1048933e48c0db142f32bcf4be8",
		"javax.inject-1-javadoc.jar":                 "f938e8eb481314d7306ae16ad91998409c8c8056bf336bc0732b4a07ad4a4f44",
		"checker-qual-3.43.0-javadoc.jar":            "3656d585e50b9a29f4d34890245c5a44ec40fbf795a61692fbf50eb1e9d15e18",
		"annotations-23.0.0-javadoc.jar":             "631038d3c232e65f0f427885c397a9ea13a368b2e67a2748d6f874781cb884a2",
		"checker-qual-3.33.0-javadoc.jar":            "c17b3d3a8c3963948fc98aef682c5406b91c87e8f164c22787f69c2f97b488f5",
		"core-3.5.4-javadoc.jar":                     "b45555b43a243ad17fd733b4551675ad2441c72b5d0a8d4ba8f9e2e37c7c6404",
		"error_prone_annotations-2.18.0-javadoc.jar": "4d3bc035aa67b73ae1d738966a49ad5ca1b079427695e79156851025767ec7ca",
		"failureaccess-1.0.1-javadoc.jar":            "93ac95225225e06945575f64f6ebb615bf799dad6aa7d26fe51927a5a080967b",
		"guava-32.0.1-android-javadoc.jar":           "e6f12cded824b34039cb4d7a5459c4441b2c234a258990d3b47c50991e4a8f23",
		"j2objc-annotations-2.8-javadoc.jar":         "ae5f3b672ace4d59f53e3b8b2d0bcd3838dd2d423d2b6e075f5085590bac2c94",
		"jspecify-1.0.0-javadoc.jar":                 "c9e92e607ea8ab965451e5f0fc8f9b2881e0d8908920c557d97389c78b877e7a",
		"jsr305-3.0.2-javadoc.jar":                   "3791d601c8757344a5b9714a1122e2f852743114a9d55c1b1fed64b13116c353",
	}
	for artifact, checksum := range javadocArtifacts {
		pattern := regexp.MustCompile(
			`<artifact name="` + regexp.QuoteMeta(artifact) + `">\s*` +
				`<sha256 value="` + checksum + `" origin="(?:Google Maven|Maven Central) HTTPS bytes independently matched to Gradle cache"/>\s*` +
				`</artifact>`,
		)
		if !pattern.MatchString(verification) {
			t.Errorf("Gradle dependency verification is missing reviewed Javadoc %s", artifact)
		}
	}
	for _, required := range []string{
		`<artifact name="aapt2-9.2.1-15009934-linux.jar">`,
		`<sha256 value="755f6727fb3f4cce5e319eac0f3618ed4b36b49a46d4bb2cbb6fa8e9175a54d6"`,
		`<artifact name="aapt2-proto-9.2.1-15009934-sources.jar">`,
		`<sha256 value="29cc59746f656f875173f4a223734514594f99a8407e5a7f5ee33fcba4f90c08" origin="Android Studio source artifact; Gradle cache content address verified"/>`,
		`<artifact name="symbol-processing-gradle-plugin-2.3.10-sources.jar">`,
		`<sha256 value="df743d7056404d9e6286d14ca234fd75fad1771d65d4d87b0231f0b1d02b7365" origin="Android Studio source artifact; Gradle cache content address verified"/>`,
		`<artifact name="gradle-9.4.1-src.zip">`,
		`<sha256 value="e07d5ab9a5ee05064d2cea472ad2d8b46144c75d598080e5f77660d18c0e3020" origin="Official Gradle distribution source checksum verified"/>`,
		`<component group="org.jetbrains.kotlin" name="kotlin-gradle-plugins-bom" version="2.2.10">`,
		`<sha256 value="e4b7dd0b5570aa7ae6597d1f479bcea94e78e12735fa86f80afa95e7014efed6"`,
		`<sha256 value="c0a5a21a4e6eec4d8bb6a2c491fac42f35ab9f08dd2af6bedb085715ac805296"`,
	} {
		if !strings.Contains(verification, required) {
			t.Errorf("Gradle dependency verification metadata is missing %q", required)
		}
	}
	build := string(readRepositoryFile(t, "android", "build.gradle.kts"))
	for _, required := range []string{
		`providers.gradleProperty("android.injected.invoked.from.ide")`,
		`LockMode.DEFAULT else LockMode.STRICT`,
	} {
		if !strings.Contains(build, required) {
			t.Errorf("Gradle dependency locking policy is missing %q", required)
		}
	}
	benchmarkLock := string(readRepositoryFile(t, "android", "benchmark", "gradle.lockfile"))
	if !regexp.MustCompile(`(?m)^empty=[^\r\n]*\bandroidApis\b`).MatchString(benchmarkLock) {
		t.Fatal("benchmark dependency lock is missing Android Studio's tooling-only androidApis configuration")
	}
}

func TestGradleWrapperIsExecutableInGit(t *testing.T) {
	command := exec.Command("git", "ls-files", "--stage", "--", "android/gradlew")
	command.Dir = filepath.Join("..", "..")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(output), "100755 ") {
		t.Fatalf("android/gradlew Git mode must be 100755, got %q", strings.TrimSpace(string(output)))
	}
}

func TestVersionCatalogContainsNoDynamicVersions(t *testing.T) {
	catalog := string(readRepositoryFile(t, "android", "gradle", "libs.versions.toml"))
	dynamic := regexp.MustCompile(`(?m)^\s*[A-Za-z0-9_.-]+\s*=\s*"(?:latest[.-].*|\+|.*\.\+)"\s*$`)
	if match := dynamic.FindString(catalog); match != "" {
		t.Fatalf("dynamic dependency version found: %s", match)
	}
}

func TestNativeBuildRemovesHostIdentityAndUsesStableSONAME(t *testing.T) {
	gradle := string(readRepositoryFile(t, "android", "core", "native-jni", "build.gradle.kts"))
	for _, required := range []string{
		"-trimpath",
		"-buildvcs=false",
		"-buildid=",
		"-B=none",
		"--build-id=none",
		"-soname,libkurdistan_bridge.so",
	} {
		if !strings.Contains(gradle, required) {
			t.Errorf("Go bridge build is missing %q", required)
		}
	}
	cmake := string(readRepositoryFile(t, "android", "core", "native-jni", "src", "main", "cpp", "CMakeLists.txt"))
	for _, required := range []string{
		`IMPORTED_SONAME "libkurdistan_bridge.so"`,
		"-ffile-prefix-map=",
		"-fdebug-prefix-map=",
		"-fmacro-prefix-map=",
		"-Wl,--build-id=none",
	} {
		if !strings.Contains(cmake, required) {
			t.Errorf("JNI build is missing %q", required)
		}
	}
}

func readRepositoryFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
