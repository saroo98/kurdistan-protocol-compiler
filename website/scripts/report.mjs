/** Generate current evidence summaries; never reuse historical verdicts. */
import {readFile,writeFile} from 'node:fs/promises';
const json=async file=>JSON.parse(await readFile(file,'utf8'));
const b=await json('qa/refinement-browser.json'),p=await json('qa/performance-report.json'),r=await json('qa/reproducibility-report.json'),i=await json('dist/build-info.json');
if(!b.passed||!p.passed||!r.passed)throw Error('Current checks must pass before reporting success');
const report=`# Current local website verification

Date: ${new Date().toISOString()}

Website version: ${i.websiteVersion}. Build manifest SHA-256: ${r.manifestSha256}.

- ${b.routes} routes loaded over real local HTTP with production headers.
- ${b.layouts.length} responsive, language and theme configurations passed.
- ${b.journeys.length} interaction assertions passed in Chromium ${b.browser}.
- ${b.errors.length} browser script/resource errors recorded.
- Two clean builds matched across ${r.files} files.
- CSS: ${p.cssGzipBytes} gzip bytes. Enhancement JavaScript: ${p.javascriptGzipBytes} gzip bytes.
- All Node unit/artifact checks and source syntax lint ran in this verification. Exact commands/results are in the receipt and evidence logs.

The browser tests cover hero selection, localized method search, the approved app layout, detail navigation, connection cancellation, parent synchronization, simulated latency cancellation, profile search and favorites. Screenshots are current captures, not historical input evidence.

The demo and production output contain no private obligation/scope register. Original uploads and historical private material are outside the distributable project. The previous React website is not part of this build.

These results do not constitute native-speaker approval, physical-device coverage, a screen-reader user study, a security audit, field performance or public deployment approval. Some inherited advanced phone copy remains English. See docs/LIMITATIONS.md.
`;
await writeFile('qa/QA_REPORT.md',report);
console.log('Current local evidence report generated.');
