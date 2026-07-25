# Chrome 150 command-line extension loading unsupported

## Classification

Browser capability boundary; not a candidate, extension-runtime, or service-worker defect.

## Evidence

The branded Google Chrome 150 executable and Guard-launched process were proven, and the exact candidate path appeared on its command line. No Study Copilot worker appeared. An initially observed worker belonged to Chrome's built-in Google Network Speech extension and was later rejected by exact manifest matching.

## Correction

Phase 2C now resolves Playwright 1.61.0's bundled Chromium revision 1228, launches it through a persistent context, and requires the candidate's manifest-declared `background.js` worker. The corrective canary observed Study Copilot and completed runtime-origin attestation readback.

## Lesson

Google Chrome process success did not prove that the chosen browser supported unpacked extension side-loading. The canary failed before exercising the candidate runtime.
